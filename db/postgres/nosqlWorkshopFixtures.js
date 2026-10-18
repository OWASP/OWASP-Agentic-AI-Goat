'use strict';
// Static curriculum fixtures copied from the legacy seed; no SQLite runtime dependency.
const NOSQLI_OBJECTIVE_IDS = [
  'nosqli_1', 'nosqli_2', 'nosqli_3', 'nosqli_4', 'nosqli_5',
  'nosqli_6', 'nosqli_7', 'nosqli_8', 'nosqli_9', 'nosqli_10',
];

const PAPERS = [
  {
    paper_id: 'PAPER-2024-001',
    title: 'Attention Is All You Need',
    abstract: 'The dominant sequence transduction models are based on complex recurrent or convolutional neural networks. We propose a new simple network architecture, the Transformer, based solely on attention mechanisms, dispensing with recurrence and convolutions entirely.',
    authors: JSON.stringify(['Ashish Vaswani', 'Noam Shazeer', 'Niki Parmar', 'Jakob Uszkoreit']),
    topics: JSON.stringify(['deep learning', 'transformers', 'NLP', 'attention mechanisms']),
    year: 2017, journal: 'NeurIPS', citations: 87420, cited_by: JSON.stringify(['PAPER-2024-003', 'PAPER-2024-007', 'PAPER-2024-010']),
    url: 'https://arxiv.org/abs/1706.03762'
  },
  {
    paper_id: 'PAPER-2024-002',
    title: 'BERT: Pre-training of Deep Bidirectional Transformers for Language Understanding',
    abstract: 'We introduce a new language representation model called BERT, which stands for Bidirectional Encoder Representations from Transformers. BERT is designed to pre-train deep bidirectional representations from unlabeled text.',
    authors: JSON.stringify(['Jacob Devlin', 'Ming-Wei Chang', 'Kenton Lee', 'Kristina Toutanova']),
    topics: JSON.stringify(['NLP', 'pre-training', 'transformers', 'language models']),
    year: 2019, journal: 'NAACL', citations: 62100, cited_by: JSON.stringify(['PAPER-2024-007']),
    url: 'https://arxiv.org/abs/1810.04805'
  },
  {
    paper_id: 'PAPER-2024-003',
    title: 'GPT-4 Technical Report',
    abstract: 'We report the development of GPT-4, a large-scale multimodal model which can accept image and text inputs and produce text outputs. GPT-4 exhibits human-level performance on various professional and academic benchmarks.',
    authors: JSON.stringify(['OpenAI Research Team']),
    topics: JSON.stringify(['large language models', 'multimodal AI', 'GPT', 'NLP']),
    year: 2023, journal: 'arXiv', citations: 15200, cited_by: JSON.stringify(['PAPER-2024-008']),
    url: 'https://arxiv.org/abs/2303.08774'
  },
  {
    paper_id: 'PAPER-2024-004',
    title: 'Deep Residual Learning for Image Recognition',
    abstract: 'We present a residual learning framework to ease the training of networks that are substantially deeper than those used previously. We provide comprehensive empirical evidence showing that these residual networks are easier to optimize.',
    authors: JSON.stringify(['Kaiming He', 'Xiangyu Zhang', 'Shaoqing Ren', 'Jian Sun']),
    topics: JSON.stringify(['computer vision', 'deep learning', 'residual networks', 'image recognition']),
    year: 2016, journal: 'CVPR', citations: 98500, cited_by: JSON.stringify(['PAPER-2024-005']),
    url: 'https://arxiv.org/abs/1512.03385'
  },
  {
    paper_id: 'PAPER-2024-005',
    title: 'Generative Adversarial Networks',
    abstract: 'We propose a new framework for estimating generative models via an adversarial process, in which we simultaneously train two models: a generative model G that captures the data distribution, and a discriminative model D.',
    authors: JSON.stringify(['Ian Goodfellow', 'Jean Pouget-Abadie', 'Mehdi Mirza', 'Bing Xu']),
    topics: JSON.stringify(['generative models', 'deep learning', 'GANs', 'unsupervised learning']),
    year: 2014, journal: 'NeurIPS', citations: 55800, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/1406.2661'
  },
  {
    paper_id: 'PAPER-2024-006',
    title: 'Adversarial Examples Are Not Easily Detected: Bypassing Ten Detection Methods',
    abstract: 'Neural networks are vulnerable to adversarial examples. We investigate ten proposed detection methods and show that all ten can be defeated by a combined attack, demonstrating the fragility of current defenses.',
    authors: JSON.stringify(['Nicholas Carlini', 'David Wagner']),
    topics: JSON.stringify(['cybersecurity', 'adversarial ML', 'neural networks', 'attack detection']),
    year: 2017, journal: 'AISec Workshop', citations: 3200, cited_by: JSON.stringify(['PAPER-2024-009']),
    url: 'https://arxiv.org/abs/1705.07263'
  },
  {
    paper_id: 'PAPER-2024-007',
    title: 'Language Models are Few-Shot Learners',
    abstract: 'We demonstrate that scaling language models greatly improves task-agnostic, few-shot performance. GPT-3, with 175 billion parameters, achieves strong performance on many NLP datasets.',
    authors: JSON.stringify(['Tom Brown', 'Benjamin Mann', 'Nick Ryder', 'Melanie Subbiah']),
    topics: JSON.stringify(['large language models', 'few-shot learning', 'NLP', 'GPT']),
    year: 2020, journal: 'NeurIPS', citations: 28900, cited_by: JSON.stringify(['PAPER-2024-003', 'PAPER-2024-008']),
    url: 'https://arxiv.org/abs/2005.14165'
  },
  {
    paper_id: 'PAPER-2024-008',
    title: 'Constitutional AI: Harmlessness from AI Feedback',
    abstract: 'As AI systems become more capable, we need to train them to be both helpful and safe. We present Constitutional AI, a method for training harmless AI assistants using a set of principles.',
    authors: JSON.stringify(['Yuntao Bai', 'Saurav Kadavath', 'Sandipan Kundu', 'Amanda Askell']),
    topics: JSON.stringify(['AI safety', 'RLHF', 'constitutional AI', 'alignment']),
    year: 2022, journal: 'arXiv', citations: 4100, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/2212.08073'
  },
  {
    paper_id: 'PAPER-2024-009',
    title: 'Prompt Injection Attacks and Defenses in LLM-Integrated Applications',
    abstract: 'We systematically investigate prompt injection attacks in LLM-integrated applications. We define threat models, catalog attack types, and evaluate defenses. Our study shows current defenses are insufficient against adaptive attacks.',
    authors: JSON.stringify(['Yupei Liu', 'Yuqi Jia', 'Runpeng Geng', 'Jinyuan Jia']),
    topics: JSON.stringify(['cybersecurity', 'prompt injection', 'LLM security', 'AI attacks']),
    year: 2023, journal: 'arXiv', citations: 890, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/2310.12815'
  },
  {
    paper_id: 'PAPER-2024-010',
    title: 'Scaling Laws for Neural Language Models',
    abstract: 'We study empirical scaling laws for language model performance on the cross-entropy loss. The loss scales as a power-law with model size, dataset size, and the amount of compute used for training.',
    authors: JSON.stringify(['Jared Kaplan', 'Sam McCandlish', 'Tom Henighan', 'Tom B. Brown']),
    topics: JSON.stringify(['scaling laws', 'language models', 'deep learning', 'NLP']),
    year: 2020, journal: 'arXiv', citations: 12400, cited_by: JSON.stringify(['PAPER-2024-003', 'PAPER-2024-007']),
    url: 'https://arxiv.org/abs/2001.08361'
  },
  {
    paper_id: 'PAPER-2024-011',
    title: 'Federated Learning: Challenges, Methods, and Future Directions',
    abstract: 'Federated learning enables privacy-preserving training of machine learning models across distributed devices. This survey covers the challenges of communication efficiency, systems heterogeneity, privacy, and fairness.',
    authors: JSON.stringify(['Tian Li', 'Anit Kumar Sahu', 'Ameet Talwalkar', 'Virginia Smith']),
    topics: JSON.stringify(['federated learning', 'privacy', 'distributed systems', 'machine learning']),
    year: 2020, journal: 'IEEE Signal Processing Magazine', citations: 5600, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/1908.07873'
  },
  {
    paper_id: 'PAPER-2024-012',
    title: 'Diffusion Models Beat GANs on Image Synthesis',
    abstract: 'We show that diffusion models can achieve image sample quality superior to the current state-of-the-art generative models. We achieve this on unconditional image synthesis by finding a better architecture through a series of ablations.',
    authors: JSON.stringify(['Prafulla Dhariwal', 'Alexander Quinn Nichol']),
    topics: JSON.stringify(['generative models', 'diffusion models', 'image synthesis', 'computer vision']),
    year: 2021, journal: 'NeurIPS', citations: 8700, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/2105.05233'
  },
  {
    paper_id: 'PAPER-2024-013',
    title: 'The Mythos of Model Interpretability',
    abstract: 'Interpretability in machine learning has become an important area of research. We argue that interpretability is not a single, well-defined concept, and that researchers should specify which aspects of interpretability they seek.',
    authors: JSON.stringify(['Zachary Lipton']),
    topics: JSON.stringify(['interpretability', 'explainable AI', 'machine learning', 'AI safety']),
    year: 2018, journal: 'ACM Queue', citations: 4900, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/1606.03490'
  },
  {
    paper_id: 'PAPER-2024-014',
    title: 'Reinforcement Learning from Human Feedback',
    abstract: 'We show an approach to align language models with human preferences using reinforcement learning from human feedback. Human feedback is used to train a reward model, which is then used to optimize the language model policy.',
    authors: JSON.stringify(['Paul Christiano', 'Jan Leike', 'Tom Brown', 'Miljan Martic']),
    topics: JSON.stringify(['RLHF', 'alignment', 'reinforcement learning', 'language models']),
    year: 2017, journal: 'NeurIPS', citations: 3800, cited_by: JSON.stringify(['PAPER-2024-008']),
    url: 'https://arxiv.org/abs/1706.03741'
  },
  {
    paper_id: 'PAPER-2024-015',
    title: 'Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks',
    abstract: 'We explore a general-purpose fine-tuning recipe for retrieval-augmented generation (RAG) — models which combine pre-trained parametric and non-parametric memory for language generation.',
    authors: JSON.stringify(['Patrick Lewis', 'Ethan Perez', 'Aleksandra Piktus', 'Fabio Petroni']),
    topics: JSON.stringify(['RAG', 'NLP', 'information retrieval', 'language models']),
    year: 2020, journal: 'NeurIPS', citations: 6800, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/2005.11401'
  },
  {
    paper_id: 'PAPER-2024-016',
    title: 'Neural Architecture Search with Reinforcement Learning',
    abstract: 'We use a recurrent network to generate the model descriptions of neural networks and train this RNN with reinforcement learning to maximize the expected accuracy of the generated architectures on a validation set.',
    authors: JSON.stringify(['Barret Zoph', 'Quoc V. Le']),
    topics: JSON.stringify(['neural architecture search', 'AutoML', 'reinforcement learning', 'deep learning']),
    year: 2017, journal: 'ICLR', citations: 7200, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/1611.01578'
  },
  {
    paper_id: 'PAPER-2024-017',
    title: 'Data-Efficient Image Recognition with Contrastive Predictive Coding',
    abstract: 'We propose contrastive predictive coding (CPC) for unsupervised feature learning. CPC uses a contrastive loss to learn representations that predict future observations in latent space.',
    authors: JSON.stringify(['Olivier Hénaff', 'Aravind Srinivas', 'Jeffrey De Fauw', 'Ali Razavi']),
    topics: JSON.stringify(['contrastive learning', 'self-supervised learning', 'computer vision', 'representation learning']),
    year: 2020, journal: 'ICML', citations: 2900, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/1905.09272'
  },
  {
    paper_id: 'PAPER-2024-018',
    title: 'Robustness and Reliability in Machine Learning Systems',
    abstract: 'We survey current approaches to building reliable machine learning systems, covering distribution shift, adversarial robustness, uncertainty estimation, and out-of-distribution detection.',
    authors: JSON.stringify(['Dan Hendrycks', 'Nicholas Carlini', 'John Schulman', 'Jacob Steinhardt']),
    topics: JSON.stringify(['robustness', 'reliability', 'machine learning', 'AI safety']),
    year: 2021, journal: 'arXiv', citations: 1500, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/2107.03342'
  },
  {
    paper_id: 'PAPER-2024-019',
    title: 'Large-Scale Study of Curiosity-Driven Learning',
    abstract: 'We perform a large-scale empirical study of curiosity as an intrinsic reward signal for reinforcement learning. We test curiosity across 54 environments and find it leads to consistent improvements in exploration.',
    authors: JSON.stringify(['Yuri Burda', 'Harri Edwards', 'Deepak Pathak', 'Amos Storkey']),
    topics: JSON.stringify(['reinforcement learning', 'curiosity', 'exploration', 'intrinsic motivation']),
    year: 2019, journal: 'ICLR', citations: 1800, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/1808.04355'
  },
  {
    paper_id: 'PAPER-2024-020',
    title: 'Graph Neural Networks: A Review of Methods and Applications',
    abstract: 'We provide a comprehensive review of graph neural networks (GNNs), covering the theoretical foundations, model architectures, and key applications in social networks, bioinformatics, and computer vision.',
    authors: JSON.stringify(['Jie Zhou', 'Ganqu Cui', 'Shengding Hu', 'Zhengyan Zhang']),
    topics: JSON.stringify(['graph neural networks', 'deep learning', 'social networks', 'bioinformatics']),
    year: 2020, journal: 'AI Open', citations: 4300, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/1812.08434'
  },
  // Expanded catalog — additional topics
  {
    paper_id: 'PAPER-2024-021',
    title: 'YOLOv7: Trainable Bag-of-Freebies Sets New State-of-the-Art for Real-Time Object Detectors',
    abstract: 'YOLOv7 surpasses all known object detectors in both speed and accuracy in the range from 5 FPS to 160 FPS. It achieves 56.8% AP on the MS COCO dataset at 30 FPS or higher on GPU V100.',
    authors: JSON.stringify(['Chien-Yao Wang', 'Alexey Bochkovskiy', 'Hong-Yuan Mark Liao']),
    topics: JSON.stringify(['object detection', 'computer vision', 'real-time ML', 'YOLO']),
    year: 2022, journal: 'CVPR', citations: 8900, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/2207.02696'
  },
  {
    paper_id: 'PAPER-2024-022',
    title: 'Foundation Models for Robotics: Applications, Challenges, and the Future',
    abstract: 'We survey recent advances in applying large foundation models — including LLMs, vision-language models, and diffusion models — to robotics tasks such as manipulation, navigation, and task planning.',
    authors: JSON.stringify(['Russ Tedrake', 'Chelsea Finn', 'Sergey Levine', 'Pieter Abbeel']),
    topics: JSON.stringify(['robotics', 'foundation models', 'AI agents', 'manipulation', 'planning']),
    year: 2023, journal: 'arXiv', citations: 3100, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/2312.07843'
  },
  {
    paper_id: 'PAPER-2024-023',
    title: 'Not All Tokens Are What You Need',
    abstract: 'We find that during language model pre-training, tokens corresponding to semantically rich content contribute disproportionately to learning. We propose selective token training to improve efficiency without degrading quality.',
    authors: JSON.stringify(['Zhenghao Lin', 'Zhibin Gou', 'Yeyun Gong', 'Xiao Liu']),
    topics: JSON.stringify(['NLP', 'language model pre-training', 'token selection', 'efficiency']),
    year: 2023, journal: 'arXiv', citations: 890, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/2402.00657'
  },
  {
    paper_id: 'PAPER-2024-024',
    title: 'A Survey on Large Language Model-based Autonomous Agents',
    abstract: 'We present a comprehensive survey of LLM-based autonomous agents, covering agent construction (profile, memory, planning, action), applications (single-agent, multi-agent, human-agent), and evaluation strategies.',
    authors: JSON.stringify(['Lei Wang', 'Chen Ma', 'Xueyang Feng', 'Zeyu Zhang']),
    topics: JSON.stringify(['AI agents', 'large language models', 'autonomous systems', 'multi-agent', 'planning']),
    year: 2024, journal: 'Frontiers of Computer Science', citations: 5600, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/2308.11432'
  },
  {
    paper_id: 'PAPER-2024-025',
    title: 'Universal and Transferable Adversarial Attacks on Aligned Language Models',
    abstract: 'We demonstrate that adversarial attacks can be constructed that reliably bypass the safety filters of aligned LLMs. These attacks transfer across models and represent a fundamental challenge for AI safety.',
    authors: JSON.stringify(['Andy Zou', 'Zifan Wang', 'J. Zico Kolter', 'Matt Fredrikson']),
    topics: JSON.stringify(['adversarial attacks', 'AI safety', 'cybersecurity', 'LLM security', 'alignment']),
    year: 2023, journal: 'arXiv', citations: 2400, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/2307.15043'
  },
  // --- Batch 3: Multimodal, Knowledge Graphs, Speech, Recommendation, Meta-learning ---
  {
    paper_id: 'PAPER-2024-026',
    title: 'CLIP: Learning Transferable Visual Models From Natural Language Supervision',
    abstract: 'We present CLIP which efficiently learns visual concepts from natural language supervision. CLIP pre-trains an image encoder and a text encoder to predict which of N×N possible (image, text) pairings across a batch actually occurred.',
    authors: JSON.stringify(['Alec Radford', 'Jong Wook Kim', 'Chris Hallacy', 'Aditya Ramesh']),
    topics: JSON.stringify(['multimodal AI', 'vision-language models', 'contrastive learning', 'computer vision', 'NLP']),
    year: 2021, journal: 'ICML', citations: 24300, cited_by: JSON.stringify(['PAPER-2024-028']),
    url: 'https://arxiv.org/abs/2103.00020'
  },
  {
    paper_id: 'PAPER-2024-027',
    title: 'Flamingo: a Visual Language Model for Few-Shot Learning',
    abstract: 'We introduce Flamingo, a family of Visual Language Models (VLM) with a few-shot learning capability. Flamingo bridges powerful pre-trained vision-only and language-only models, handling sequences of arbitrarily interleaved visual and textual data.',
    authors: JSON.stringify(['Jean-Baptiste Alayrac', 'Jeff Donahue', 'Pauline Luc', 'Antoine Miech']),
    topics: JSON.stringify(['multimodal AI', 'vision-language models', 'few-shot learning', 'large language models']),
    year: 2022, journal: 'NeurIPS', citations: 4100, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/2204.14198'
  },
  {
    paper_id: 'PAPER-2024-028',
    title: 'DALL·E 2: Hierarchical Text-Conditional Image Generation with CLIP Latents',
    abstract: 'We present a two-stage approach to text-to-image generation. DALL·E 2 uses CLIP to map text descriptions to image embeddings and a diffusion model to decode those embeddings into highly realistic images.',
    authors: JSON.stringify(['Aditya Ramesh', 'Prafulla Dhariwal', 'Alex Nichol', 'Casey Chu']),
    topics: JSON.stringify(['text-to-image', 'generative models', 'diffusion models', 'multimodal AI', 'CLIP']),
    year: 2022, journal: 'arXiv', citations: 7600, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/2204.06125'
  },
  {
    paper_id: 'PAPER-2024-029',
    title: 'Knowledge Graph Embedding: A Survey of Approaches and Applications',
    abstract: 'We provide a comprehensive survey of knowledge graph embedding methods, covering translation-based models (TransE, TransH), semantic matching models (RESCAL, DistMult), and deep learning-based approaches.',
    authors: JSON.stringify(['Quan Wang', 'Zhendong Mao', 'Bin Wang', 'Li Guo']),
    topics: JSON.stringify(['knowledge graphs', 'graph embeddings', 'representation learning', 'information extraction']),
    year: 2017, journal: 'IEEE TKDE', citations: 8200, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/1503.00759'
  },
  {
    paper_id: 'PAPER-2024-030',
    title: 'Wav2Vec 2.0: A Framework for Self-Supervised Learning of Speech Representations',
    abstract: 'We show for the first time that learning powerful representations from speech audio alone followed by fine-tuning on transcribed speech can outperform the best semi-supervised methods while being conceptually simpler.',
    authors: JSON.stringify(['Alexei Baevski', 'Yuhao Zhou', 'Abdelrahman Mohamed', 'Michael Auli']),
    topics: JSON.stringify(['speech recognition', 'self-supervised learning', 'audio processing', 'NLP']),
    year: 2020, journal: 'NeurIPS', citations: 9800, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/2006.11477'
  },
  {
    paper_id: 'PAPER-2024-031',
    title: 'Neural Collaborative Filtering',
    abstract: 'We present NCF, a neural network framework for collaborative filtering. By replacing the inner product with a neural architecture, NCF captures non-linear and complex user-item interactions beyond matrix factorisation.',
    authors: JSON.stringify(['Xiangnan He', 'Lizi Liao', 'Hanwang Zhang', 'Liqiang Nie']),
    topics: JSON.stringify(['recommendation systems', 'collaborative filtering', 'deep learning', 'matrix factorization']),
    year: 2017, journal: 'WWW', citations: 7100, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/1708.05031'
  },
  {
    paper_id: 'PAPER-2024-032',
    title: 'Model-Agnostic Meta-Learning for Fast Adaptation of Deep Networks',
    abstract: 'We propose MAML, an algorithm compatible with any model trained with gradient descent. MAML trains a model to rapidly adapt to new tasks using only a small number of gradient steps and training examples.',
    authors: JSON.stringify(['Chelsea Finn', 'Pieter Abbeel', 'Sergey Levine']),
    topics: JSON.stringify(['meta-learning', 'few-shot learning', 'deep learning', 'optimization']),
    year: 2017, journal: 'ICML', citations: 14500, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/1703.03400'
  },
  {
    paper_id: 'PAPER-2024-033',
    title: 'MobileNetV3: Searching for MobileNetV3',
    abstract: 'We present MobileNetV3, optimized for mobile phone CPUs using a combination of hardware-aware NAS, NetAdapt algorithm, and novel architectural designs. MobileNetV3-Large achieves state-of-the-art accuracy at reduced latency.',
    authors: JSON.stringify(['Andrew Howard', 'Ruoming Pang', 'Hartwig Adam', 'Quoc V. Le']),
    topics: JSON.stringify(['model compression', 'edge AI', 'efficient deep learning', 'computer vision', 'mobile ML']),
    year: 2019, journal: 'ICCV', citations: 6500, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/1905.02244'
  },
  {
    paper_id: 'PAPER-2024-034',
    title: 'LoRA: Low-Rank Adaptation of Large Language Models',
    abstract: 'We propose LoRA, which freezes the pre-trained model weights and injects trainable rank decomposition matrices into each layer. LoRA reduces the number of trainable parameters by 10,000x and GPU memory requirements by 3x.',
    authors: JSON.stringify(['Edward Hu', 'Yelong Shen', 'Phillip Wallis', 'Zeyuan Allen-Zhu']),
    topics: JSON.stringify(['fine-tuning', 'parameter-efficient learning', 'large language models', 'NLP', 'model compression']),
    year: 2022, journal: 'ICLR', citations: 18700, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/2106.09685'
  },
  {
    paper_id: 'PAPER-2024-035',
    title: 'Causal Inference in Statistics: An Overview',
    abstract: 'This paper reviews the mathematical foundations of causal inference including potential outcomes, structural causal models, do-calculus, and the identification of causal effects from observational data.',
    authors: JSON.stringify(['Judea Pearl']),
    topics: JSON.stringify(['causal inference', 'statistics', 'machine learning', 'causality', 'probabilistic reasoning']),
    year: 2009, journal: 'Statistics Surveys', citations: 11200, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/1206.6955'
  },
  {
    paper_id: 'PAPER-2024-036',
    title: 'Temporal Fusion Transformers for Interpretable Multi-horizon Time Series Forecasting',
    abstract: 'We present TFT, a novel attention-based architecture combining high-performance multi-horizon forecasting with interpretable insights into temporal dynamics. TFT uses variable selection networks and multi-head attention.',
    authors: JSON.stringify(['Bryan Lim', 'Sercan Arik', 'Nicolas Loeff', 'Tomas Pfister']),
    topics: JSON.stringify(['time series', 'forecasting', 'transformers', 'interpretability', 'deep learning']),
    year: 2021, journal: 'International Journal of Forecasting', citations: 3400, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/1912.09363'
  },
  {
    paper_id: 'PAPER-2024-037',
    title: 'Neurosymbolic AI: The 3rd Wave',
    abstract: 'We review the history of neurosymbolic AI from early hybrid systems to modern neural-symbolic integration. We discuss current approaches that combine neural perception with symbolic reasoning and highlight open challenges.',
    authors: JSON.stringify(['Artur d\'Avila Garcez', 'Luis C. Lamb']),
    topics: JSON.stringify(['neurosymbolic AI', 'symbolic reasoning', 'knowledge representation', 'deep learning', 'hybrid AI']),
    year: 2023, journal: 'arXiv', citations: 1900, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/2012.05876'
  },
  {
    paper_id: 'PAPER-2024-038',
    title: 'Mixtral of Experts: A High Quality Sparse Mixture of Experts Model',
    abstract: 'We introduce Mixtral 8x7B, a sparse mixture of experts language model. Mixtral has the same architecture as Mistral 7B, with the feedforward blocks replaced by a mixture-of-experts layer, outperforming GPT-3.5 on most benchmarks.',
    authors: JSON.stringify(['Albert Q. Jiang', 'Alexandre Sablayrolles', 'Antoine Roux', 'Arthur Mensch']),
    topics: JSON.stringify(['mixture of experts', 'large language models', 'sparse models', 'NLP', 'efficient inference']),
    year: 2024, journal: 'arXiv', citations: 4200, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/2401.04088'
  },
  {
    paper_id: 'PAPER-2024-039',
    title: 'Segment Anything',
    abstract: 'We introduce the Segment Anything Model (SAM) and the SA-1B dataset with over 1 billion masks. SAM is a promptable segmentation model trained on SA-1B and demonstrates strong zero-shot generalisation to new image distributions.',
    authors: JSON.stringify(['Alexander Kirillov', 'Eric Mintun', 'Nikhila Ravi', 'Hanzi Mao']),
    topics: JSON.stringify(['image segmentation', 'computer vision', 'foundation models', 'zero-shot learning']),
    year: 2023, journal: 'ICCV', citations: 11400, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/2304.02643'
  },
  {
    paper_id: 'PAPER-2024-040',
    title: 'Chain-of-Thought Prompting Elicits Reasoning in Large Language Models',
    abstract: 'We explore how generating a chain of thought — a series of intermediate reasoning steps — significantly improves the ability of large language models to perform complex reasoning. With chain-of-thought prompting, 540B parameter models achieve state-of-the-art results on math and commonsense reasoning benchmarks.',
    authors: JSON.stringify(['Jason Wei', 'Xuezhi Wang', 'Dale Schuurmans', 'Maarten Bosma']),
    topics: JSON.stringify(['chain-of-thought', 'reasoning', 'large language models', 'prompting', 'NLP']),
    year: 2022, journal: 'NeurIPS', citations: 9700, cited_by: JSON.stringify([]),
    url: 'https://arxiv.org/abs/2201.11903'
  },
];

const AUTHORS = [
  { author_id: 'AUTH-001', name: 'Ashish Vaswani', institution: 'Google Brain', expertise: JSON.stringify(['transformers', 'attention mechanisms', 'NLP']), paper_count: 23, email: 'vaswani@google.com', bio: 'Research scientist at Google Brain focusing on neural network architectures for sequence modelling.' },
  { author_id: 'AUTH-002', name: 'Noam Shazeer', institution: 'Google Research', expertise: JSON.stringify(['NLP', 'transformers', 'mixture of experts']), paper_count: 18, email: 'noam@google.com', bio: 'Co-author of the Transformer paper. Research scientist specialising in scalable ML architectures.' },
  { author_id: 'AUTH-003', name: 'Jacob Devlin', institution: 'Google AI', expertise: JSON.stringify(['NLP', 'pre-training', 'BERT', 'language models']), paper_count: 14, email: 'jacobdevlin@google.com', bio: 'Lead researcher on BERT. Focuses on pre-trained language models and transfer learning.' },
  { author_id: 'AUTH-004', name: 'Ian Goodfellow', institution: 'Apple', expertise: JSON.stringify(['GANs', 'generative models', 'adversarial examples', 'deep learning']), paper_count: 52, email: 'ian@apple.com', bio: 'Inventor of Generative Adversarial Networks. Author of the deep learning textbook.' },
  { author_id: 'AUTH-005', name: 'Kaiming He', institution: 'Meta AI Research', expertise: JSON.stringify(['computer vision', 'residual networks', 'image recognition']), paper_count: 31, email: 'kaiminghe@meta.com', bio: 'Research scientist at Meta AI. Creator of ResNets and the He initialisation method.' },
  { author_id: 'AUTH-006', name: 'Nicholas Carlini', institution: 'Google DeepMind', expertise: JSON.stringify(['cybersecurity', 'adversarial ML', 'ML security', 'privacy']), paper_count: 47, email: 'carlini@google.com', bio: 'Security researcher studying adversarial examples, privacy attacks, and AI security.' },
  { author_id: 'AUTH-007', name: 'Tom Brown', institution: 'Anthropic', expertise: JSON.stringify(['large language models', 'GPT', 'NLP', 'scaling']), paper_count: 19, email: 'tbrown@anthropic.com', bio: 'Lead author of GPT-3. Research scientist focused on large-scale language model training.' },
  { author_id: 'AUTH-008', name: 'Yuntao Bai', institution: 'Anthropic', expertise: JSON.stringify(['AI alignment', 'constitutional AI', 'RLHF', 'AI safety']), paper_count: 11, email: 'yuntao@anthropic.com', bio: 'Research scientist at Anthropic working on AI alignment and safety techniques.' },
  { author_id: 'AUTH-009', name: 'Jared Kaplan', institution: 'Anthropic', expertise: JSON.stringify(['scaling laws', 'language models', 'physics of AI']), paper_count: 15, email: 'jared@anthropic.com', bio: 'Physicist turned AI researcher. Pioneer of scaling laws for neural networks.' },
  { author_id: 'AUTH-010', name: 'Paul Christiano', institution: 'Alignment Research Center', expertise: JSON.stringify(['RLHF', 'AI alignment', 'iterated amplification', 'safety']), paper_count: 22, email: 'paul@alignment.org', bio: 'Founder of ARC. Pioneered reinforcement learning from human feedback for AI alignment.' },
  { author_id: 'AUTH-011', name: 'Tian Li', institution: 'University of Wisconsin-Madison', expertise: JSON.stringify(['federated learning', 'distributed ML', 'optimization']), paper_count: 16, email: 'tianli@wisc.edu', bio: 'Assistant Professor specialising in federated learning and distributed optimisation.' },
  { author_id: 'AUTH-012', name: 'Prafulla Dhariwal', institution: 'OpenAI', expertise: JSON.stringify(['diffusion models', 'generative models', 'computer vision']), paper_count: 9, email: 'prafulla@openai.com', bio: 'Research scientist at OpenAI. Lead author of diffusion model breakthroughs.' },
  { author_id: 'AUTH-013', name: 'Patrick Lewis', institution: 'Meta AI Research', expertise: JSON.stringify(['RAG', 'information retrieval', 'NLP', 'open-domain QA']), paper_count: 12, email: 'plewis@meta.com', bio: 'Research scientist focused on retrieval-augmented generation and open-domain QA systems.' },
  { author_id: 'AUTH-014', name: 'Dan Hendrycks', institution: 'Center for AI Safety', expertise: JSON.stringify(['robustness', 'AI safety', 'distribution shift', 'out-of-distribution detection']), paper_count: 38, email: 'dan@safe.ai', bio: 'Director of the Center for AI Safety. Works on robustness, safety, and ethics in ML.' },
  { author_id: 'AUTH-015', name: 'Zachary Lipton', institution: 'Carnegie Mellon University', expertise: JSON.stringify(['interpretability', 'explainable AI', 'clinical ML', 'NLP']), paper_count: 29, email: 'zlipton@cmu.edu', bio: 'Associate Professor at CMU. Researcher on model interpretability and responsible ML.' },
  { author_id: 'AUTH-016', name: 'Alec Radford', institution: 'OpenAI', expertise: JSON.stringify(['multimodal AI', 'vision-language models', 'GPT', 'contrastive learning']), paper_count: 21, email: 'alec@openai.com', bio: 'Research scientist at OpenAI. Co-creator of GPT series and CLIP. Pioneer in self-supervised multimodal learning.' },
  { author_id: 'AUTH-017', name: 'Chelsea Finn', institution: 'Stanford University', expertise: JSON.stringify(['meta-learning', 'robotics', 'few-shot learning', 'reinforcement learning']), paper_count: 44, email: 'cbfinn@stanford.edu', bio: 'Assistant Professor at Stanford. Creator of MAML. Researches meta-learning, robotics, and generalisation.' },
  { author_id: 'AUTH-018', name: 'Sergey Levine', institution: 'UC Berkeley', expertise: JSON.stringify(['robotics', 'reinforcement learning', 'imitation learning', 'meta-learning']), paper_count: 87, email: 'svlevine@berkeley.edu', bio: 'Professor at UC Berkeley. Leads the Robotic AI and Learning Lab. Works on deep RL for physical manipulation.' },
  { author_id: 'AUTH-019', name: 'Judea Pearl', institution: 'UCLA', expertise: JSON.stringify(['causal inference', 'Bayesian networks', 'probabilistic reasoning', 'causality']), paper_count: 143, email: 'judea@cs.ucla.edu', bio: 'Turing Award winner. Professor at UCLA. Inventor of Bayesian networks and the do-calculus framework for causal reasoning.' },
  { author_id: 'AUTH-020', name: 'Alexei Baevski', institution: 'Meta AI Research', expertise: JSON.stringify(['speech recognition', 'self-supervised learning', 'audio processing', 'representation learning']), paper_count: 17, email: 'abaevski@meta.com', bio: 'Research scientist at Meta AI. Creator of wav2vec 2.0. Focuses on self-supervised speech and audio representation learning.' },
  { author_id: 'AUTH-021', name: 'Xiangnan He', institution: 'University of Science and Technology of China', expertise: JSON.stringify(['recommendation systems', 'collaborative filtering', 'graph neural networks', 'information retrieval']), paper_count: 58, email: 'xiangnanhe@ustc.edu.cn', bio: 'Professor at USTC. Works on recommender systems, neural collaborative filtering, and knowledge graph-enhanced recommendations.' },
  { author_id: 'AUTH-022', name: 'Edward Hu', institution: 'Microsoft Research', expertise: JSON.stringify(['parameter-efficient fine-tuning', 'LoRA', 'large language models', 'NLP']), paper_count: 8, email: 'edwardhu@microsoft.com', bio: 'Research scientist at Microsoft Research. Creator of LoRA, enabling efficient fine-tuning of large language models.' },
  { author_id: 'AUTH-023', name: 'Jason Wei', institution: 'Google DeepMind', expertise: JSON.stringify(['chain-of-thought prompting', 'reasoning', 'large language models', 'emergent capabilities']), paper_count: 19, email: 'jasonwei@google.com', bio: 'Research scientist at Google DeepMind. Introduced chain-of-thought prompting and studies emergent abilities of LLMs.' },
  { author_id: 'AUTH-024', name: 'Alexander Kirillov', institution: 'Meta AI Research', expertise: JSON.stringify(['image segmentation', 'computer vision', 'foundation models', 'object detection']), paper_count: 22, email: 'akirillov@meta.com', bio: 'Research scientist at Meta AI Research. Lead author of Segment Anything Model (SAM). Works on universal vision models.' },
  { author_id: 'AUTH-025', name: 'Bryan Lim', institution: 'University of Oxford', expertise: JSON.stringify(['time series forecasting', 'temporal fusion transformers', 'deep learning', 'interpretability']), paper_count: 14, email: 'bryanlim@oxford.ac.uk', bio: 'Associate Professor at Oxford. Creator of Temporal Fusion Transformers. Researches interpretable deep learning for forecasting.' },
];

// Pre-seeded reading list for nova_demo_user
const READING_LIST = [
  { user_id: 'nova_demo_user', paper_id: 'PAPER-2024-001' },  // Attention Is All You Need
  { user_id: 'nova_demo_user', paper_id: 'PAPER-2024-007' },  // GPT-3 Few-Shot
  { user_id: 'nova_demo_user', paper_id: 'PAPER-2024-009' },  // Prompt Injection
  { user_id: 'nova_demo_user', paper_id: 'PAPER-2024-024' },  // LLM Agents Survey
  { user_id: 'nova_demo_user', paper_id: 'PAPER-2024-034' },  // LoRA
  { user_id: 'nova_demo_user', paper_id: 'PAPER-2024-040' },  // Chain-of-Thought
  { user_id: 'nova_demo_user', paper_id: 'PAPER-2024-026' },  // CLIP
];


module.exports = { PAPERS, AUTHORS, READING_LIST, NOSQLI_OBJECTIVE_IDS };
