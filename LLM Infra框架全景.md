# LLM Infra 框架全景:训练、推理与 RL 后训练

> **文档定位**:转行 LLM infra 的框架版图 + 学习路径。按 infra 分层视角组织(显存/通信/并行,不讲纯算法),每个框架回答三个问题:**它解决什么工程问题、核心机制是什么、和相邻框架什么关系**。
>
> **写作时点**:2026-10-13。框架动态部分经当日检索核实;版本号等时效信息以各仓库为准。
>
> **与已有笔记的关系**:文中多处回指《GRPO 原理与 verl 源码深度解析》(下称 *GRPO 笔记*)与并行系列图解(下称 *五把刀*)——verl 那条线你已走通过,本文负责把剩余版图补齐。

---

## 0. 开篇:一张六层地图

先建立"框架住在哪一层"的物理图景。整个 LLM infra 栈可以切成六层,上层是下层的"配置 + 编排":

```
┌─────────────────────────────────────────────────────────────┐
│ ⑥ 服务编排层   API 网关 / 路由 / P-D 分离调度                  │
│               (Ray Serve, BentoML, Mooncake 调度面)          │
├─────────────────────────────────────────────────────────────┤
│ ⑤ RL 后训练框架  把训练引擎和推理引擎"焊"在一起                  │
│               (verl / OpenRLHF / slime / NeMo-RL / AReaL)   │
├─────────────────────────────────────────────────────────────┤
│ ④ 引擎层       训练侧:并行策略的运行时                         │
│               (FSDP2 / Megatron-Core / DeepSpeed)           │
│               推理侧:批调度 + KV cache 管理                   │
│               (vLLM / SGLang / TensorRT-LLM)                │
├─────────────────────────────────────────────────────────────┤
│ ③ 集群编排层   把多机多卡变成一个"资源池"                       │
│               (Ray / Slurm / Kubernetes)                    │
├─────────────────────────────────────────────────────────────┤
│ ② 通信层       NCCL / HCCL / RCCL(集合通信原语)              │
├─────────────────────────────────────────────────────────────┤
│ ① 算子层       FlashAttention / FlashInfer / DeepGEMM /      │
│               CUTLASS / Triton(单个 kernel 的极致)          │
└─────────────────────────────────────────────────────────────┘
```

**为什么这张地图对转行者重要**:招聘 JD 上的每个高频词都能定位到某一层——"熟悉 vLLM"是 ④,"掌握 NCCL 调优"是 ②,"MoE all-to-all 优化"横跨 ①②④。面试官问的深度也按层分布:低层问"原理与手写"(比如 online softmax 为什么省显存),高层问"选型与排障"(比如 P/D 分离什么时候值得做)。

**一个贯穿全文的结构性事实**:⑤ 的 RL 框架不是"又一个框架",而是 ③④ 层组件的粘合剂——verl = FSDP/Megatron(训练)+ vLLM/SGLang(rollout)+ Ray(编排),这正是你 *GRPO 笔记* §3 里拆过的 hybrid engine。所以学版图的正确顺序不是把每层都学完再拼起来,而是**先学两个引擎(一个训练、一个推理),再看 RL 框架怎么用它们**。

各层 2026 年的主流玩家速览:

| 层 | 主流项目 | 出品方 |
|---|---|---|
| ① 算子 | FlashAttention 2/3, FlashInfer, DeepGEMM, FlashMLA, CUTLASS, Triton | 各界(NVIDIA/DeepSeek/高校) |
| ② 通信 | NCCL, HCCL, RCCL, MSCCL++ | NVIDIA / 华为 / AMD / 微软 |
| ③ 编排 | Ray, Slurm, K8s + Operator | UCB / 社区 / CNCF |
| ④ 训练引擎 | FSDP2, Megatron-Core(+NeMo), DeepSpeed, torchtitan | Meta / NVIDIA / 微软 / PyTorch |
| ④ 推理引擎 | vLLM, SGLang, TensorRT-LLM;端侧 llama.cpp | UCB / LMSYS / NVIDIA / 社区 |
| ⑤ RL 后训练 | verl, OpenRLHF, slime(+vime), AReaL, NeMo-RL | 字节 / 社区 / 智谱 / 蚂蚁 / NVIDIA |
| ⑥ 服务 | Mooncake, LMCache, Ray Serve, Triton Inference Server | 月之暗面 / 社区 / 各厂 |

---

## 1. 训练框架层:显存墙与两条切分路线

### 1.0 训练框架到底解决什么问题

一句话:**单卡放不下的模型权重 + 优化器状态,怎么切到多卡上还不让 GPU 饿着**。

先把账算实。混合精度 + Adam 训练一个 7B 模型,每参数的显存构成(与 *GRPO 笔记* §1.1 同一套数字):

| 状态 | 精度 | 每参数字节 |
|---|---|---|
| 权重 | bf16 | 2 |
| 梯度 | bf16 | 2 |
| 权重 master 副本 | fp32 | 4 |
| Adam 一阶动量 m | fp32 | 4 |
| Adam 二阶动量 v | fp32 | 4 |
| **合计** | | **16** |

7B × 16 B = **112 GB**,单张 A100/H100(80 GB)连 7B 全参训练都装不下,还得留激活值显存。70B 就是 1.1 TB。所以"训练框架"的第一性任务就是**切显存**,而一切显存都归属三样东西:优化器态(m+v,占 8/16)、参数(master,占 4/16)、梯度(占 2/16)。

两条切分路线,对应两大家族:

- **路线 A:按"数据并行维度"切状态**(ZeRO/FSDP 家族)。模型结构不动,把优化器态/梯度/参数沿 DP 组均匀切片,每卡只存 1/N;forward 前用 all-gather 临时拼回完整层参数,backward 用 reduce-scatter 归并梯度。核心通信原语你已经在 *五把刀* 里拆过——就是 ring all-reduce 的两半。
- **路线 B:把模型结构本身切开**(Megatron 家族)。TP 把单个矩阵乘按列/行切到多卡(层内 all-reduce),PP 把层序列切段(层间 point-to-point)。模型每张卡上都不完整,但单卡上的"这个瞬间"也是不完整的。

这条分野决定了后面所有框架差异,值得花一分钟记住:**A 切的是"训练状态",B 切的是"模型图"**。

### 1.1 PyTorch FSDP2:官方原生路线

**是什么**:Fully Sharded Data Parallel,PyTorch 原生的 ZeRO-3 实现。FSDP2 是 2024 年底起合入的重写版,把 FSDP1 的"按 module 分片"改成"按参数分片",底层用 DTensor(分布式张量抽象)描述"这个参数在哪个进程组上被怎么切"。

**为什么值得在意 DTensor**:它让"参数"本身携带分布信息,于是 FSDP2 可以和 TP/PP/EP 原生组合成 2D/3D 并行,而不用像 FSDP1 那样靠钩子硬拼。这也是 PyTorch 官方栈(FSDP2 + torch.compile + async tensor parallel)的技术底座。

**工程账**:ZeRO-3 等级的切分不是免费的——通信量从 DDP 的 1× 参数量(单次 all-reduce,实际 2× 数据量)涨到约 **1.5×**(forward all-gather + backward all-gather + reduce-scatter)。换来的收益:显存占用从 16 B/param 降到 16/N + 常数。N 越大越省,但通信越凶——这是为什么 FSDP 系在**中小模型(≤70B)+ 中等规模集群**最舒服。

**与你已学内容的接口**:verl 的 `fsdp_workers.py` 就是这条线。你在 *GRPO 笔记* §3.4 看过的 reshard(模型在 actor 组与 DP 组之间重新切分)之所以能做,底层就是 FSDP 把参数当 DTensor 切来切去的能力。

### 1.2 Megatron-LM / Megatron-Core / NeMo:NVIDIA 路线

**是什么**:Megatron-LM 是 NVIDIA 的大模型训练参考实现仓库,2019 年以 TP(tensor parallel)论文起家;后来把并行原语抽成了独立库 **Megatron-Core**(TP/PP/CP/EP/DP + 混合并行 + 重计算 + MoE 支持),Megatron-LM 退居"官方示例脚本";**NeMo** 则是在 Megatron-Core 之上再包一层的完整训练框架(数据、模型、回调、多模态)。

**三层关系一句话**:Megatron-Core 是发动机,Megatron-LM 是 NVIDIA 的改装示范车,NeMo 是整车交付版。

**为什么它是生产标配**:路线 B 的并行需要改模型代码本身(把 `nn.Linear` 换成列切/行切的 `ColumnParallelLinear`),这个脏活在 Megatron-Core 里已经为 Llama/Qwen/DeepSeek 等主流结构做好了,且和 NCCL、Tensor Core、FP8 的协同优化最深。2025-2026 的行业现实是:**各家自研训练栈大多以 Megatron-Core 为骨架 fork**,连华为昇腾的 MindSpeed-LLM 也对齐它的接口(`use_mcore_models=True`)。

**两个必会的工程机制**:

1. **Distributed Optimizer**:朴素 DP 下,每张卡都存全量优化器态(8 B/param 的冗余 × DP 数)。Megatron 的做法是把优化器态沿 DP 组再切一刀,每卡只算自己那 1/N 的 m/v——对 16 B/param 的账本,这一刀就省下近半显存。
2. **3D 并行的真实排布**:*五把刀* 讲过 TP 组内 all-reduce、PP 的 1F1B 气泡;Megatron 的贡献是把 TP×PP×DP 的进程排布做成了配置学——同一组网卡,`TP=8,PP=4` 和 `TP=4,PP=8` 的通信拓扑完全不同,这正是它 `parallel_state.py` 一千多行在做的事。

### 1.3 DeepSpeed:ZeRO 的提出者,昔王今侯

**是什么**:微软出品,ZeRO(Redundancy Optimizer)三阶段的提出者,曾经是"参数切分"路线的代名词。

**必会的 ZeRO 三阶段**(面试高频,用 1.0 节的账本记):

| 阶段 | 切什么 | 显存(每卡,DP=N) | 额外通信 |
|---|---|---|---|
| ZeRO-1 | 优化器态(m+v) | 8 + 8/N | 无(通信仍可压成一次 reduce-scatter) |
| ZeRO-2 | + 梯度 | 6 + 10/N | 无(仍是标准 all-reduce 的量) |
| ZeRO-3 | + 参数 | 16/N + 常数 | +50%(forward/backward 各一次 all-gather) |

> **怎么读这张表**:分母 16 是混合精度 Adam 的每参数字节数(§1.0)。以 ZeRO-2、N=8 为例:优化器态和梯度各存 1/8,参数(2)与 master(4)仍是全量,合计 6 + 10/8 ≈ 7.25 B/param——从 16 直降一半多。N 越大越省,但 ZeRO-3 的额外通信就是 FSDP 那笔 +50% 的账。

**2026 年的真实状态**:社区热度明显让位给了 FSDP2(原生、可组合)和 Megatron 系(大规模生产),但 DeepSpeed 仍有两个不可替代的遗产——**CPU offload / NVMe offload**(ZeRO-Offload、ZeRO-Infinity,异构显存的鼻祖)和把 ZeRO 思想写进了所有后来者的 DNA。**学习建议:读论文 + 弄清三阶段显存/通信账即可,不必走读源码**。

### 1.4 torchtitan:PyTorch 官方的"参考答案"

**是什么**:PyTorch 团队 2024 年推出的 LLM 预训练 reference 实现,目标是"一台笔记本到 128 卡 H100 都能跑通",用纯 PyTorch 原生组件(FSDP2 + TP/PP/CP + torch.compile + async TP)训练 Llama。

**定位怎么理解**:它不是 Megatron 的竞品,而是"PyTorch 原生栈能做到什么程度"的官方示范——代码量小一个数量级,适合**学"并行策略如何拼装"的源码阅读入口**。2026 年 1 月官方在 GitHub 确认 PyTorch 年度路线图将包含 torchtitan 专节,仍是活跃的一等公民项目。

### 1.5 用户侧封装层(认识即可,不是深水区)

HuggingFace Accelerate/TRL、Axolotl、LLaMA-Factory 这类工具把上述引擎包成"写 YAML 就能微调"的形态,覆盖单机 LoRA/SFT/DPO 的长尾需求。工作中常遇到、面试中不深究。记住定位:**它们是 ④ 层引擎的配置器,不是引擎本身**。

### 1.6 训练框架对比表

| 框架 | 出品方 | 切分路线 | 甜区 | 学习建议(转行视角) |
|---|---|---|---|---|
| FSDP2 | Meta/PyTorch | 状态切分(ZeRO-3) | ≤70B,科研/中小集群,RL 训练器 | **必精**;verl 里已见过,补 DTensor |
| Megatron-Core(+NeMo) | NVIDIA | 模型切分(TP/PP/EP) | 百 B~千亿预训练,生产 | **必精**;"五把刀"的原厂实现 |
| DeepSpeed | 微软 | 状态切分 | 中小规模,HF 生态 | 读 ZeRO 论文,懂三阶段即可 |
| torchtitan | PyTorch | 混合(原生) | 学参考实现 | 推荐作为并行源码阅读第一站 |
| TRL / LLaMA-Factory 等 | HF/社区 | — | 单机微调 | 了解定位即可 |

**选型逻辑速记**(面试可能问"你们为什么选 X"):模型 ≤70B 且集群 ≤ 几十卡 → FSDP2,省心;百 B 级预训练或极致吞吐要求 → Megatron 系,通信拓扑可调;已有 HF 代码库要快速起训 → 两者都有接口,DeepSpeed 的历史存量最大。

---

## 2. 推理引擎层:KV cache 是一切的钥匙

### 2.0 推理引擎解决什么问题

训练框架的敌人是"参数放不下",推理引擎的敌人是**"KV cache 放不下 + 算力用不满"**。

先算 KV cache 的账(这个公式请记住,面试与排障都用得上):

$$\text{KV bytes/token} = 2 \times n_{layers} \times n_{kv\\_heads} \times d_{head} \times b$$

> **符号表**:2 指 Key 和 Value 各一份;$n_{layers}$ = Transformer 层数;$n_{kv\\_heads}$ = GQA 分组后的 KV 头数(GQA 的意义就是把多头 KV 压缩成少数几组);$d_{head}$ = 每头维度;$b$ = 每元素字节数(bf16 为 2)。

代入一个 7B 级 GQA 模型(28 层、4 个 KV 头、head_dim 128、bf16):2×28×4×128×2 ≈ **56 KB/token**。看似不多,但乘上"批大小 × 序列长度"再乘并发:一个 batch 内 32 条并发 × 8K 上下文,就是 32×8192×56 KB ≈ **15 GB**——一张 80 GB 卡塞三四个这样的 batch 就满了,而模型权重才占 14 GB。**推理时代的显存大头不是模型,是 KV cache**,这是整个 2024-2026 推理系统演进的原动力。

第二笔账是**算力浪费**:自回归 decode 每 forward 只产出 1 个 token,计算密度极低,decode 阶段是访存受限(memory-bound)——GPU 大部分算力在等 HBM 吐数据。所以推理引擎的一切技巧(continuous batching、P/D 分离、CUDA Graph)本质上都在做两件事:**让 KV cache 不浪费显存,让 GPU 不空转**。

### 2.1 vLLM:事实标准

**是什么**:UC Berkeley 2023 年出品,以 PagedAttention 论文起家,当前**开源推理引擎的事实标准**——云厂商 API 服务、RL 框架 rollout(包括 verl 的默认选项之一)的地基。

**两个奠基机制**:

1. **PagedAttention**:把 KV cache 当操作系统管物理内存一样管——切成固定大小的 block(如每块 16 个 token 的 KV),逻辑序列到物理块通过页表映射。效果:传统为每条请求预分配最大序列长度的连续 KV,显存内碎片 + 预留浪费常达 60-80%;分页后浪费率降到 **<4%**。同一序列的块还不必物理连续,这才让 prefix 复用(共享前缀块)成为可能。
2. **Continuous batching**(源自 Orca 论文):不等整批做完才换批,而是**每一步 decode 后动态移出完成序列、放入新序列**,把批组织从"静态帧"变成"滚动流"。

**2025 年的 V1 重写**:vLLM 把调度热路径重写(默认 chunked prefill、prefix caching 默认开、采样接 FlashInfer),消掉了 Python 调度瓶颈,单机吞吐显著提升。走读源码时以 `v1/` 目录为准,旧版代码路径基本退役。

**工程黑话对照**:prefill(处理整段 prompt,算力受限,可以大块并行)vs decode(逐 token 生成,访存受限)——这对区分是下一节 P/D 分离的全部伏笔。

### 2.2 SGLang:RadixAttention 与"激进内核派"

**是什么**:LMSYS 出品(与 vLLM 同源伯克利系),2024-2026 上升最猛的引擎,DeepSeek 系模型部署的主力之一。

**招牌机制 RadixAttention**:把所有已见请求的 KV cache 挂在一棵 **radix tree**(基数树)上,按 token 前缀索引。新请求到来时沿树匹配最长公共前缀,直接复用对应 KV 块。对比 vLLM 的块级 prefix cache,radix tree 的**跨请求、跨轮次、任意粒度**复用更强——agent 多轮对话、few-shot 大公共前缀、tree search 式推理场景命中率碾压。你 *GRPO 笔记* §6 里 rollout 高度重复的 prompt 前缀,正是这类复用的甜区。

**风格差异**:SGLang 走"内核激进"路线(与 FlashInfer 深度协同、overlap scheduler 让调度与计算重叠),vLLM 走"广度与生态"路线。2025-2026 两家互相追赶,TTP(时延)与吞吐的领先位置在版本间反复易手,**岗位技能上二选一深钻、另一个会用即可**。

### 2.3 TensorRT-LLM:NVIDIA 的旗舰性能参照物

**是什么**:NVIDIA 官方推理栈,把模型编译成 TensorRT 图 + 深度调优 kernel,在**最新旗舰卡(如 B200)上的吞吐/时延至今仍是公开基准里的天花板**。

**代价**:闭源内核 + NVIDIA 强绑定,新模型/新特性的支持节奏落后于 vLLM/SGLang(开源社区众包快于官方排期);近年它也在向 PyTorch backend 转型以改善迭代速度和开放性。

**转行视角的定位**:云厂商/大厂的"性能参照物"与 NVIDIA NIM 的底座;除非进 NVIDIA 生态重的团队,一般**会用、会读 benchmark 即可,不作为源码深钻首选**。

### 2.4 其他值得知道名字的引擎

- **llama.cpp / Ollama**:端侧与单机事实标准(CPU/消费卡量化推理),Ollama 是它的易用封装。Mac 本地跑模型的默认答案。
- **LMDeploy**:上海 AI Lab(InternLM 系)出品,W4A16 量化方案 TurboMind 有口碑,国产环境常见。
- **MLC-LLM**:TVM 编译路线,把 LLM 编译到各类硬件(含手机),编译器视角的教学样本。
- **TGI**:HuggingFace 出品,曾是标配之一,2025 后社区热度明显被 vLLM/SGLang 吸走。

### 2.5 2025-2026 推理架构热点:P/D 分离与 KV cache 池化

这是当前推理 infra 最活跃的前沿,也是招聘 JD 新增的高频词,值得知道"为什么"和"谁在做"。

**为什么分离 prefill 和 decode**:两者资源特征相反——prefill 吃算力(GEMM 大而满),decode 吃带宽(逐 token 访存)。混布时互相拖累:一条长 prompt 的 prefill 会阻塞同卡上所有序列的 decode(TTFT 和 ITL 互相伤害)。于是把两类阶段**拆到不同的卡池,各自按特征配置**,中间搬运 KV cache。这正是 2.0 节那笔账的延伸:KV cache 成了可搬运的"商品"。

**2026 年的落地形态**:

- **Mooncake**(月之暗面开源,Kimi 的服务平台):KVCache 为中心的架构,把集群里闲置的 **CPU DRAM / SSD 变成 KV 存储层**,prefill 与 decode 集群分离 + KV 传输调度。已通过 `MooncakeStoreConnector` 进 vLLM 官方特性。
- **LMCache**:KV cache 管理层,支持跨 vLLM 实例的 prefill→decode 交接;2025 年起与 Mooncake 联手做 KVCache 中心化服务。
- **Ray Serve** 也提供了 P/D 分离的编排层抽象。

**与你的已有知识对接**:这波演进的极端形态,就是你已见过的 DeepSeek 式**大 EP(专家并行)推理**——MoE 模型把专家沿几百卡切开后,decode 阶段的瓶颈从"KV cache 访存"变成"all-to-all 通信",*五把刀* 里 EP 的那把刀在推理侧的真实用武之地。

### 2.6 推理引擎对比表

| 引擎 | 出品方 | 招牌机制 | 强项 | 弱项 | 转行学习建议 |
|---|---|---|---|---|---|
| vLLM | UCB | PagedAttention、V1 引擎 | 生态、模型覆盖、事实标准 | 内核层相对保守 | **必精,首选深钻** |
| SGLang | LMSYS | RadixAttention、overlap 调度 | 时延、agent/结构化场景 | 生态略小 | 精一备一 |
| TensorRT-LLM | NVIDIA | 编译图 + 官方 kernel | 旗舰卡性能天花板 | 闭源、绑定、跟进慢 | 会用会读数 |
| llama.cpp/Ollama | 社区 | 量化 + CPU 推理 | 端侧、单机 | 集群服务非目标 | 了解 |
| LMDeploy / MLC-LLM / TGI | — | 各有侧重 | 场景化 | — | 知道名字与定位 |

---

## 3. RL 后训练框架层:把两个引擎焊在一起

> 你已经通过 verl 把这层的机制走通了一遍(hybrid engine、训练/推理态切换、reshard、rollout 调度)。所以本章不再讲机制本身,只做三件事:**把 verl 放回版图、给出同行的对照、讲清 2025-2026 的主战场(同步 vs 异步)**。

### 3.1 全部框架共享同一副骨架

无论哪一家,结构都是三元组:**训练引擎 × rollout 引擎 × 编排器**。

| 框架 | 训练侧 | rollout 侧 | 编排 | 出品方/背景 |
|---|---|---|---|---|
| verl | FSDP / Megatron | vLLM / SGLang | Ray | 字节 Seed(HybridFlow 论文) |
| OpenRLHF | DeepSpeed / vLLM | vLLM | Ray | 开源社区(姜鑫等) |
| slime | Megatron | SGLang(vime 亦可接 vLLM) | torch 分布式 | 智谱 THUDM |
| NeMo-RL | Megatron/NeMo | TensorRT-LLM | Ray | NVIDIA |
| AReaL | Megatron | SGLang | 自研 async 管线 | 蚂蚁 |
| TRL | transformers/accelerate | — | 单机 | HuggingFace(算法侧) |

> **怎么读这张表**:每行都是"③④ 层组件的一个组合选择"。没有一个 RL 框架自己写并行或 KV cache,它们的价值全在**焊接处**——权重同步、数据流、调度。这就是为什么本笔记把训练/推理引擎放在 RL 框架之前:引擎学扎实,RL 框架的差异一天就能看懂。

### 3.2 同行对照(相对 verl 的差异点)

- **OpenRLHF**:资历最老的开源 RLHF 框架之一,代码以简洁著称,是很多人入门的第一站。相对 verl:模型覆盖与算法广度更小,但学习曲线平缓——如果你要给别人讲 RL 训练结构,它的代码反而好读。
- **slime**:智谱出品,训练 GLM 系列的实战栈,Megatron + SGLang 组合,主打 RL Scaling。**2026-06 的 vLLM 官方 vime 把 slime 的训练侧与 vLLM 的 rollout 连通**,这个"官方认证"让它成为 verl 之外最值得留意的同步方案。
- **AReaL**:蚂蚁出品,**fully-async 路线的代表**——rollout 与训练完全解耦,靠 replay buffer 和 off-policy 修正(重算重要性权重、陈旧度控制)消化两边速度差。
- **NeMo-RL**:NVIDIA 2025 年推出,把 Megatron-NeMo + TensorRT-LLM + Ray 打包成生产级 RLHF 管线,定位"已买全套 NVIDIA 栈的企业的默认选项"。面试提一句就够,不必深钻。

### 3.3 主战场:同步 vs 异步(你已见过问题的一半)

你在 *GRPO 笔记* 的九步流程里已经见过了同步方案的代价:**rollout 期间 trainer GPU 空转、训练期间 rollout 引擎空转**——两拨卡轮流闲置,资源利用率理论上一半不到。异步方案就是冲着这个来的:

- **1-step / 2-step / 3-step 异步**:松绑程度递进——从"训练与 rollout 各推进一步再对齐"到"完全解耦流水"。
- **代价是引入 off-policy**:rollout 用的权重比当前训练权重旧(stale weight),需要 PPO 目标里的重要性采样比 $\rho = \pi_{\theta}/\pi_{\theta_{old}}$ 做修正(你在 *GRPO 笔记* §2 已见过 $\rho$ 的定义),陈旧度过大还要丢弃样本。**异步 infra 的全部工程 = 用调度换利用率,再用数学把 off-policy 误差补回来**。
- **行业现状**:2026 年 HuggingFace 有一篇综述对比了 16 个异步 RL 库;verl、OpenRLHF、slime 都已长出 async 模式,但各家实现的可信度与规模上限参差,这层目前是**最活跃也最不稳的一层**——版本迭代按月计,学机制比背实现重要。

**转行视角**:国内 RL infra 岗位(RLHF/后训练)JD 几乎必然出现 verl;异步经验(AReaL、slime async 或 verl 的 async 系列)是 2025-2026 的加分项热区。你从同步 verl 起步再补异步,是顺路。

### 3.4 轻量路线(不算 infra 深水区,但要会分清)

TRL(HF)、Axolotl、LLaMA-Factory 主要覆盖单机 SFT/DPO/LoRA。面试中若被问"你为什么不用 TRL"——标准答案:TRL 的并发与显存模型到多机 scale 出头就力不从心,那正是 verl/NeMo-RL 这层存在的理由。

---

## 4. 底层加速库:训练推理共用的"腰"

这一层跨在训练与推理之间,是"深挖党"从框架往下走的下一站。原则:**每个库只记"它省的是什么 + 谁在用"**。

### 4.1 通信层:NCCL 一家独大

**NCCL**(NVIDIA)是 GPU 集群集合通信的事实标准:all-reduce / all-gather / reduce-scatter / all-to-all 的拓扑感知实现(ring/tree 自适应,抠 NVLink 与 IB 拓扑)。**HCCL / RCCL** 是华为昇腾与 AMD ROCm 的对应物。*五把刀* 里拆过的 ring all-reduce 带宽账,实现就在这层。

**框架里的位置**:FSDP2 的通信钩子、Megatron 的进程组划分(`parallel_state.py` 建组后全走 NCCL)、推理 TP 的层内 all-reduce、MoE 的 all-to-all——**上层的所有"并行策略",落地都是 NCCL 调用序列**。性能调优岗(JD 里"NCCL 调优")做的事:调拓扑(TP 用 NVLink 域、DP 跨机)、调算法、排查慢节点。

### 4.2 GEMM 层:DeepGEMM 是 2025 的现象级

- **cuBLAS**:闭源默认,大多数场景够用。
- **CUTLASS**:NVIDIA 开源的 C++ 模板库,"自己拼一个定制 GEMM"的乐高,各框架 kernel 的底层素材。
- **DeepGEMM**:DeepSeek 2025-02 开源,**JIT 编译的 FP8 GEMM**(含 MoE 需要的 grouped GEMM),不依赖 cuBLAS,靠编译期特化把 FP8 训练/推理的矩阵乘推到接近硬件峰值——DeepSeek V3 训练成本神话的构件之一,也因此把"FP8 + JIT"变成了行业标配话题。

### 4.3 Attention 层:三大件

- **FlashAttention 系列**:把 attention 的 HBM 访问从 $O(n^2)$ 级降到 $O(n)$ 级(tiling + online softmax,全程不物化 n² 注意力矩阵)。FA2(2022)是训练标配;FA3(2024)在 Hopper 上再提 1.5-2×。**一句话把握**:它是"访存最优"的 attention kernel,训练推理全都站在它肩上。
- **FlashInfer**:为**推理**服务的 kernel 库(prefill/decode 各类变体、采样、量化 kernel),vLLM 与 SGLang 共用——理解成"两大引擎共用的 kernel 供应商"。
- **FlashMLA**:DeepSeek 开源的 MLA(多头潜在注意力)kernel,对应 KV cache 极度压缩的注意力结构,DeepSeek 系模型部署的核心件。

### 4.4 编译与执行图

- **Triton**:Python DSL 写 GPU kernel,编译到 PTX。**infra 岗位最常见的"会写一点 kernel"就指它**——OpenAI 出品,门槛比 CUDA C++ 低一个量级,FlashInfer 之外很多新 kernel 都先在 Triton 里长出来。
- **torch.compile / Inductor**:PyTorch 原生编译,配合 FSDP2 构成官方栈。
- **CUDA Graphs**:把 kernel launch 序列录成一张图一次提交,消掉**逐层 launch 开销**——decode 阶段每次只算 1 个 token,CPU 侧 launch 开销占比极高,CUDA Graph 是推理引擎的必选项(vLLM/SGLang 的 decode 快,一半功劳在这)。

### 4.5 优化器与显存技巧(框架层的减法)

- **Megatron distributed optimizer**:4.1 节已述,沿 DP 组切优化器态。
- **Muon**:2024 年冒头、2025 年经 Moonshot 的"Muon 可扩展到 LLM 训练"论文后在工业界站稳的新优化器——按该论文的 compute-optimal 对比,同等效果下训练 FLOPs 可省约一半;2026 年主流训练栈已陆续提供支持。
- **Activation checkpointing(重计算)**:不存激活,backward 时重算——用时间换显存,所有训练框架的一等公民配置。
- **CPU offload**:ZeRO-Offload 一脉,把优化器态挪到 CPU DRAM。

### 4.6 底层库速查表

| 库 | 解决什么 | 训练用 | 推理用 |
|---|---|---|---|
| NCCL/HCCL | 集合通信 | ✓ | ✓ |
| FlashAttention 2/3 | attention 访存最优 | ✓ | ✓ |
| FlashInfer | 推理 kernel 全家桶 | — | ✓(vLLM/SGLang) |
| DeepGEMM | FP8 GEMM(含 grouped) | ✓ | ✓ |
| FlashMLA | MLA 结构 kernel | — | ✓(DeepSeek 系) |
| Triton | 手写 kernel 的低门槛入口 | ✓ | ✓ |
| CUDA Graphs | 消 launch 开销 | 少 | ✓(decode 必备) |
| CUTLASS | 定制 GEMM 素材库 | ✓ | ✓ |

---

## 5. 转行学习路径:结合你的已有基础

### 5.1 先看岗位地图

JD 与框架的对应关系(按 2026 年国内市场观察):

| 岗位方向 | 典型业务 | JD 高频词 | 核心框架组合 |
|---|---|---|---|
| **推理服务/引擎岗** | 云厂商 MaaS、大厂 API、推理中台 | vLLM/SGLang、P/D 分离、KV cache、量化、CUDA Graph | vLLM + FlashInfer + CUDA/NCCL |
| **训练框架/性能岗** | 大模型公司预训练与继续训练 | Megatron、FSDP、ZeRO、NCCL 调优、FP8 | Megatron-Core + NCCL + DeepGEMM |
| **RL infra / 后训练岗** | 字节/智谱/DeepSeek 系及创业公司 | verl/RLHF、rollout 引擎、异步、调度 | verl/slime + 两个引擎 |

三个方向没有高下,只有口味:喜欢**在线系统与用户时延**选推理,喜欢**极限吞吐与底层性能**选训练,喜欢**异构编排与图更新**选 RL infra(训练态和推理态在同一批卡上轮转,是三者中最"杂技"的)。

### 5.2 你在哪里、往哪走

你的实际位置比多数转行者靠前:走完 verl×GRPO 一轮,你已见过完整三元组——FSDP 训练态、vLLM rollout、Ray 编排,以及权重 reshard、显存分池这些真正的 infra 难点。**下一步不是开新地图,而是把你见过一次的三条线各往下拧一圈**:

**P0(未来 3-6 个月,必精——直接决定简历竞争力)**

1. **vLLM 深钻**(推理侧首选):PagedAttention 论文 → V1 调度器 → chunked prefill 与 prefix cache 机制。理由:它是推理侧事实标准,岗位覆盖面最大,且你已在 rollout 语境里见过它。
2. **FSDP2 + torchtitan**:verl 的 FSDP worker 你已用过,补上 DTensor 语义与 all-gather/reduce-scatter 时机;torchtitan 代码量小,是看"并行策略如何拼装"的最佳走读对象。
3. **Megatron-Core**:把 *五把刀* 的概念落到原厂实现——重点 `parallel_state.py`(进程组路由)与 tensor_parallel/layers.py(列切/行切)。理由:生产训练的事实骨架,训练岗必考。

**P1(第二个 6 个月,熟悉)**

4. **SGLang**(RadixAttention + overlap 调度,与 vLLM 对照着看,双引擎视角是推理岗加分项)
5. **FlashInfer / DeepGEMM / Triton**:打通 ④→① 层。Triton 写一两个小 kernel(比如融合的 RMSNorm)就能在面试里撑起"会写 kernel"的一页。
6. **NCCL 深入**:带宽账你已会算,补拓扑感知(ring 在 NVLink 域内、tree 跨机)与常见调优开关。

**P2(长期跟踪,面试能聊)**

7. P/D 分离与 KV cache 池化(读 Mooncake 论文 + vLLM connector 文档,机制在 §2.5)
8. 异步 RL(vime / AReaL / verl async 系列;你在 *GRPO 笔记* §6.5 已见过 separate_async 三机制,顺着补 off-policy 修正)
9. TensorRT-LLM、DeepSpeed、Muon(各读一篇一手资料,能说清定位与取舍)

### 5.3 深挖入口:如果做源码走读,从哪个文件进

按你的走读习惯(先建物理图景再进代码),每个框架的"第一站":

| 框架 | 第一站文件 | 看什么 |
|---|---|---|
| vLLM | `vllm/v1/core/sched/`(调度)、`vllm/v1/engine/` | 批如何滚动组织、请求状态机 |
| SGLang | `sglang/srt/managers/scheduler.py`、`srt/mem_cache/radix_cache.py` | 与 vLLM 对照:radix 前缀匹配与淘汰 |
| Megatron-Core | `megatron/core/parallel_state.py`、`core/tensor_parallel/layers.py` | 五把刀的路由器;列切/行切的 forward/backward |
| torchtitan | `torchtitan/`(主训练循环 + parallel config) | 并行拼装的"官方答案",代码量最小 |
| verl | ✅ 已走读 | — |
| FlashInfer | `include/flashinfer/` 头文件树 | 按 decode/prefill/sampling 分类扫一遍 API 面 |
| DeepGEMM | `deep_gemm/` JIT 编译入口 | 编译期特化怎么做的(可只读思想) |

### 5.4 面试自检清单(打勾式)

机制与公式:

- [ ] 不看文档写出 KV bytes/token 公式并代入 7B GQA 数字(§2.0)
- [ ] ZeRO 1/2/3 各切什么、各自额外通信量(§1.3)
- [ ] 混合精度 Adam 每参数 16 B 的拆解(*GRPO 笔记* §1.1)
- [ ] FlashAttention 为什么把显存 IO 从 $O(n^2)$ 降到 $O(n)$(不物化注意力矩阵)
- [ ] PagedAttention 浪费率为什么能 <4%(分页 + 页表)
- [ ] GQA 对 KV cache 的压缩(§2.0 公式里 $n_{kv\\_heads}$ 的作用)

选型与权衡:

- [ ] FSDP 与 Megatron 各自甜区,给出"70B 单机 8 卡 vs 300B 集群"的选型话术(§1.6)
- [ ] P/D 分离的动机(prefill 算力受限 vs decode 访存受限)(§2.5)
- [ ] CUDA Graph 为什么是 decode 必备(§4.4)
- [ ] MoE 推理瓶颈从访存变 all-to-all 的因果链(§2.5)
- [ ] 同步 RL 的 GPU 空转窗口从哪来、异步的数学代价(*GRPO 笔记* §6 + §3.3)

前沿话题(能各聊 3 分钟):

- [ ] KV cache 池化(Mooncake/LMCache)的架构位置(§2.5)
- [ ] FP8 + JIT GEMM 为什么快(§4.2)
- [ ] Muon 与 AdamW 的取舍(§4.5)
- [ ] 异步 RL 的 1/2/3-step 松绑(§3.3)

---

## 6. 附录

### 6.1 全版图速查表

| 层 | 框架 | 一句话定位 |
|---|---|---|
| 训练 | FSDP2 | PyTorch 原生参数切分,科研默认 |
| 训练 | Megatron-Core / NeMo | 模型切分原厂,生产预训练事实骨架 |
| 训练 | DeepSpeed | ZeRO 提出者,读论文懂三阶段即可 |
| 训练 | torchtitan | PyTorch 官方参考实现,走读第一站 |
| 推理 | vLLM | 事实标准,PagedAttention + V1 |
| 推理 | SGLang | RadixAttention,时延与 agent 场景 |
| 推理 | TensorRT-LLM | NVIDIA 旗舰性能参照物 |
| 推理 | llama.cpp / Ollama | 端侧与单机默认答案 |
| RL | verl | 你已深挖;字节系,生态最大 |
| RL | OpenRLHF | 老牌简洁,入门友好 |
| RL | slime + vime | 智谱系,RL scaling,2026 官方热度 |
| RL | AReaL | 蚂蚁系,fully-async 代表 |
| RL | NeMo-RL | NVIDIA 全家桶打包 |
| 算子 | FlashAttention / FlashInfer / DeepGEMM / FlashMLA / Triton / CUTLASS | §4 |
| 通信 | NCCL / HCCL / RCCL | 集合通信唯一之层 |
| 服务 | Mooncake / LMCache / Ray Serve | KV 池化与 P/D 分离编排 |

### 6.2 延伸阅读(一手来源优先)

- vLLM Mooncake 集成文档:docs.vllm.ai(MooncakeStoreConnector 用法)
- Mooncake 项目:kvcache-ai/Mooncake(Kimi 服务平台的 KVCache 中心架构)
- LMCache×Mooncake 合作说明与 Disaggregated Prefill 文档:docs.lmcache.ai
- slime:THUDM/slime;vLLM vime 公告:vllm.ai 博客(2026-06)
- 异步 RL 综述:HuggingFace 博客《Keep the Tokens Flowing: 16 个开源异步 RL 库的经验》(2026-03)
- torchtitan 2026 路线:pytorch/torchtitan GitHub issue(2026-01-14 起)
- RL 框架横评:Anyscale《Open Source RL Libraries for LLMs》
- ZeRO / PagedAttention / Orca / Megatron 各自原始论文(论文号略,检索即得)

---

*完 · 2026-10-13 · 呼应系列:《GRPO 原理与 verl 源码深度解析》《GRPO 一步的旅程》《五把刀》并行图解*
