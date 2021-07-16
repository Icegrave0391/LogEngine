# LogEngine

## 关于Intel Processor Trace

已经整合入 **Linux Perf Tools**，详细手册详见[manual](https://man7.org/linux/man-pages/man1/perf-intel-pt.1.html)。    
关于Intel PT的详细使用说明，参考[wiki](https://perf.wiki.kernel.org/index.php/Perf_tools_support_for_Intel%C2%AE_Processor_Trace#What_is_Intel.C2.AE_Processor_Trace)。*特别推荐详细阅读该网站*。

此外，一些博客也对Intel PT的使用进行了一系列的详细说明，以及资料收集。
* [Andi Kleen's Blog](http://halobates.de/blog/p/406)：对有关PT的资源进行了索引和整理，收纳了许多相关的网站。
* [Practical Linux tracing ( Part I/X ) : symbols, debug symbols and stack unwinding](https://medium.com/coccoc-engineering-blog/things-you-should-know-to-begin-playing-with-linux-tracing-tools-part-i-x-225aae1aaf13)：使用简明样例展示了Perf工具进行采集时对程序符号的收集方式，并介绍了相关的流程。

## 关于angr

[angr](https://github.com/angr/angr)是一个开源的二进制分析平台，无稳定版本并处于持续地开发状态，其最大的亮点是支持非常多state-of-the-art的分析。
* 关于angr的使用方式和一般概念，参考：[top-level-accessible methods](https://docs.angr.io/core-concepts/toplevel)。
* 关于angr的API手册以及相关接口，参考：[API Reference](http://angr.io/api-doc/)。

## 关于LogEngine

**LogEngine**现阶段仍然作为简易demo，通过分析系统采集得到的audit log以及pt trace，进行攻击的溯源与取证分析。该工具的设计过程采用自顶向下模块化的思想，将整个项目分为不同的模块：

--> Project     
--> |_ audit     
--> |_ pt     
--> |_ factory     
--> |_ analyses     
------->|_ execution_flow     
------->|_ data_flow     

* Project：借鉴angr中的命名格式（阅读源码时注意区分`angr.Project`与`LogEngine.Project`，该项目与angr的Project模块采用相同的命名，并调用angr模块，确实容易混淆），作为分析的主控部分，与各个模块和功能进行交互。

* audit：对audit log进行解析，并重建相关数据结构和图模型。
* pt：对pt trace进行解析，并重建相关数据结构。
* factory：负责描述通过pt trace解析得到的binary信息（如*basic block*），并提供相关的底层接口。（**注：该模块和angr.factory.block高度重合，也容易引起混淆。这样设计的目的是能够拓展angr.block中的相关功能（如添加syscall、plt信息等）**）
* analyses：进行控制流的重建以及数据流分析。
  * execution_flow：分析pt_trace得到的控制流，生成图模型。
  * data_flow：完整的过程间静态数据流分析系统（拓展自angr中的**ReachingDefinitionAnalysis**）。

## 关于ReachingDefinitionAnalysis（RDA）

项目基于angr中的[ReachingDefinitions]()。
对于ReachingDefinitions，Degrigis有一篇博客描述其功能：[A reaching definition engine for binary analysis built-in in angr.](https://degrigis.github.io/posts/angr_rd/)。该博客详细地介绍了ReachingDefinitions模块的工作流程以及使用说明，能够帮助上手。然而，遗憾的是，ReachingDefinitions是一个Intra-procedural Data Flow Analysis的模版，并不支持过程间的分析。

Pamplemousse作为该模块的开发者，正在进行过程间数据流分析的研究，并提供了拓展该RDA，实现过程间分析的简略教程，见其博客[Handle function calls during static analysis in angr](https://blog.xaviermaso.com/2021/02/25/Handle-function-calls-during-static-analysis-with-angr.html)。
由于该项目正在进行科研，作者并没有将该完整项目进行开源，因此需要自行实现，个人实现过程中的所有问题可以参考issue: [bits_of_static_binary_analysis](https://github.com/Pamplemousse/bits_of_static_binary_analysis/issues/1)。

**🌟强烈建议阅读angr实现ReachingDefinitions的完整源码。然而这个过程是非常痛苦的。**





