'use strict';

/**
 * AI artifact detection.
 *
 * Scans a project directory for evidence of AI/ML components:
 *   - HuggingFace config.json  (local model weights)
 *   - GGUF / GGML files        (quantized local models)
 *   - ONNX files               (exported inference models)
 *   - PyTorch .pt/.bin files   (unsafe pickle format — threat flag)
 *   - SafeTensors files        (safe weights format)
 *   - Training artifacts       (training_args.bin, hyperparameters.json)
 *   - Python source files      (scanned for from_pretrained() model IDs)
 *   - .env files               (scanned for MODEL_ID / provider env vars)
 */

const fs   = require('fs');
const path = require('path');

const HF_CONFIG_SIGNALS = new Set([
    '_name_or_path', 'model_type', 'architectures',
    'transformers_version', 'pretrained_config_type',
]);

const SKIP_DIRS = new Set([
    'node_modules', '.git', 'vendor', 'dist', 'build',
    '__pycache__', '.venv', 'venv', '.tox', 'target', '.cache',
]);

// Python packages that signal AI usage — keyed by pip package name (lowercase)
const AI_PYTHON_PACKAGES = {
    // Core frameworks
    'torch':                  { role: 'framework',    label: 'PyTorch'                    },
    'torchvision':            { role: 'framework',    label: 'PyTorch'                    },
    'torchaudio':             { role: 'framework',    label: 'PyTorch'                    },
    'tensorflow':             { role: 'framework',    label: 'TensorFlow'                 },
    'tf-keras':               { role: 'framework',    label: 'TensorFlow'                 },
    'keras':                  { role: 'framework',    label: 'Keras'                      },
    'jax':                    { role: 'framework',    label: 'JAX'                        },
    'flax':                   { role: 'framework',    label: 'JAX'                        },
    // HuggingFace ecosystem
    'transformers':           { role: 'framework',    label: 'HuggingFace Transformers'   },
    'diffusers':              { role: 'framework',    label: 'HuggingFace Diffusers'      },
    'datasets':               { role: 'framework',    label: 'HuggingFace Datasets'       },
    'tokenizers':             { role: 'framework',    label: 'HuggingFace Tokenizers'     },
    'accelerate':             { role: 'framework',    label: 'HuggingFace Accelerate'     },
    'peft':                   { role: 'training',     label: 'HuggingFace PEFT'           },
    'trl':                    { role: 'training',     label: 'HuggingFace TRL'            },
    'sentence-transformers':  { role: 'framework',    label: 'Sentence Transformers'      },
    // Local inference runtimes
    'llama-cpp-python':       { role: 'runtime',      label: 'llama.cpp'                  },
    'ctransformers':          { role: 'runtime',      label: 'CTransformers'              },
    'ollama':                 { role: 'runtime',      label: 'Ollama'                     },
    'vllm':                   { role: 'runtime',      label: 'vLLM'                       },
    'lmdeploy':               { role: 'runtime',      label: 'LMDeploy'                   },
    'text-generation-inference': { role: 'runtime',   label: 'HuggingFace TGI'            },
    // ONNX
    'onnxruntime':            { role: 'runtime',      label: 'ONNX Runtime'               },
    'onnxruntime-gpu':        { role: 'runtime',      label: 'ONNX Runtime GPU'           },
    'optimum':                { role: 'runtime',      label: 'HuggingFace Optimum'        },
    // External AI API SDKs
    'openai':                 { role: 'api-sdk', label: 'OpenAI',      provider: 'openai'     },
    'anthropic':              { role: 'api-sdk', label: 'Anthropic',   provider: 'anthropic'  },
    'google-generativeai':    { role: 'api-sdk', label: 'Google Gemini', provider: 'google'   },
    'cohere':                 { role: 'api-sdk', label: 'Cohere',      provider: 'cohere'     },
    'mistralai':              { role: 'api-sdk', label: 'Mistral AI',  provider: 'mistral'    },
    'together':               { role: 'api-sdk', label: 'Together AI', provider: 'together'   },
    'groq':                   { role: 'api-sdk', label: 'Groq',        provider: 'groq'       },
    'boto3':                  { role: 'api-sdk', label: 'AWS Bedrock', provider: 'aws'        },
    // Orchestration & RAG
    'langchain':              { role: 'orchestration', label: 'LangChain'                 },
    'langchain-openai':       { role: 'orchestration', label: 'LangChain'                 },
    'langchain-anthropic':    { role: 'orchestration', label: 'LangChain'                 },
    'langchain-community':    { role: 'orchestration', label: 'LangChain'                 },
    'llama-index':            { role: 'orchestration', label: 'LlamaIndex'                },
    'llama_index':            { role: 'orchestration', label: 'LlamaIndex'                },
    'haystack-ai':            { role: 'orchestration', label: 'Haystack'                  },
    'autogen':                { role: 'orchestration', label: 'AutoGen'                   },
    'crewai':                 { role: 'orchestration', label: 'CrewAI'                    },
    // Quantization / fine-tuning
    'bitsandbytes':           { role: 'training', label: 'BitsAndBytes'                   },
    'auto-gptq':              { role: 'training', label: 'AutoGPTQ'                       },
    'autoawq':                { role: 'training', label: 'AutoAWQ'                        },
    'deepspeed':              { role: 'training', label: 'DeepSpeed'                      },
    'pytorch-lightning':      { role: 'training', label: 'PyTorch Lightning'              },
    // MLOps / experiment tracking
    'wandb':                  { role: 'mlops', label: 'Weights & Biases'                  },
    'mlflow':                 { role: 'mlops', label: 'MLflow'                            },
    'neptune-client':         { role: 'mlops', label: 'Neptune'                           },
    // Vector stores
    'chromadb':               { role: 'vector-store', label: 'Chroma'                    },
    'pinecone-client':        { role: 'vector-store', label: 'Pinecone'                  },
    'weaviate-client':        { role: 'vector-store', label: 'Weaviate'                  },
    'qdrant-client':          { role: 'vector-store', label: 'Qdrant'                    },
    'faiss-cpu':              { role: 'vector-store', label: 'FAISS'                      },
    'faiss-gpu':              { role: 'vector-store', label: 'FAISS'                      },
};

// Patterns to extract HF model IDs from Python source
const MODEL_ID_REGEXPS = [
    /from_pretrained\(\s*["']([a-zA-Z0-9][\w\-.]*\/[\w\-.]+)["']/g,
    /pipeline\(\s*["'][^"']+["']\s*,\s*model\s*=\s*["']([a-zA-Z0-9][\w\-.]*\/[\w\-.]+)["']/g,
    /model\s*=\s*["']([a-zA-Z0-9][\w\-.]*\/[\w\-.]+)["']/g,
    /snapshot_download\(\s*["']([a-zA-Z0-9][\w\-.]*\/[\w\-.]+)["']/g,
    /hf_hub_download\(\s*["']([a-zA-Z0-9][\w\-.]*\/[\w\-.]+)["']/g,
    // Common proprietary model name patterns (no slash)
    /model\s*=\s*["'](gpt-[\w.-]+|claude-[\w.-]+|gemini-[\w.-]+|mistral-[\w.-]+|command-[\w.-]+|llama[\w.-]+)["']/g,
];

// .env variable names that reveal which model is in use
const ENV_MODEL_VARS = [
    { re: /^OPENAI_MODEL\s*=\s*(.+)$/m,          provider: 'openai'      },
    { re: /^ANTHROPIC_MODEL\s*=\s*(.+)$/m,        provider: 'anthropic'   },
    { re: /^GEMINI_MODEL\s*=\s*(.+)$/m,           provider: 'google'      },
    { re: /^MISTRAL_MODEL\s*=\s*(.+)$/m,          provider: 'mistral'     },
    { re: /^COHERE_MODEL\s*=\s*(.+)$/m,           provider: 'cohere'      },
    { re: /^(?:HF_MODEL|HUGGINGFACE_MODEL)\s*=\s*(.+)$/m, provider: 'huggingface' },
    { re: /^MODEL_(?:ID|NAME)\s*=\s*(.+)$/m,      provider: 'unknown'     },
    { re: /^BEDROCK_MODEL\s*=\s*(.+)$/m,          provider: 'aws'         },
];

/**
 * Walk `dir` and categorise AI-relevant files.
 * Returns structured buckets; each entry has at least { path }.
 */
function detectAIArtifacts(dir, { maxDepth = 4 } = {}) {
    const out = {
        hfConfigs:         [],
        ggufFiles:         [],
        onnxFiles:         [],
        safetensors:       [],
        pytorchBins:       [],
        trainingArtifacts: [],
        pythonFiles:       [],
        envFiles:          [],
    };

    function walk(cur, depth) {
        if (depth > maxDepth) return;
        let entries;
        try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { return; }

        for (const e of entries) {
            if (e.isDirectory()) {
                if (!SKIP_DIRS.has(e.name)) walk(path.join(cur, e.name), depth + 1);
                continue;
            }
            const full = path.join(cur, e.name);
            const lo   = e.name.toLowerCase();

            if (lo === 'config.json')                    out.hfConfigs.push({ path: full, dir: cur });
            else if (lo.endsWith('.gguf') || lo.endsWith('.ggml'))  out.ggufFiles.push({ path: full });
            else if (lo.endsWith('.onnx'))               out.onnxFiles.push({ path: full });
            else if (lo.endsWith('.safetensors'))        out.safetensors.push({ path: full });
            else if ((lo.endsWith('.pt') || lo.endsWith('.pth') || lo === 'pytorch_model.bin')
                      && !lo.includes('optimizer'))       out.pytorchBins.push({ path: full });
            else if (lo === 'training_args.bin' || lo === 'hyperparameters.json'
                      || lo.startsWith('trainer_state')) out.trainingArtifacts.push({ path: full });
            else if (lo.endsWith('.py') && depth <= 3)  out.pythonFiles.push({ path: full });
            else if (lo === '.env' || lo === '.env.local' || lo === '.env.example') out.envFiles.push({ path: full });
        }
    }

    walk(dir, 0);
    return out;
}

/**
 * Parse a HuggingFace config.json.
 * Returns null if the file doesn't look like an HF model config.
 */
function parseHFConfig(filePath) {
    try {
        const raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        if (!Object.keys(raw).some(k => HF_CONFIG_SIGNALS.has(k))) return null;
        return {
            modelId:             raw._name_or_path || null,
            modelType:           raw.model_type    || null,
            architectures:       raw.architectures || [],
            transformersVersion: raw.transformers_version || null,
            torchDtype:          raw.torch_dtype   || null,
        };
    } catch { return null; }
}

/**
 * Read first 24 bytes of a GGUF file to confirm format and extract version.
 */
function parseGGUFHeader(filePath) {
    try {
        const fd  = fs.openSync(filePath, 'r');
        const buf = Buffer.alloc(24);
        const n   = fs.readSync(fd, buf, 0, 24, 0);
        fs.closeSync(fd);
        if (n < 8 || buf.toString('ascii', 0, 4) !== 'GGUF') return null;
        return {
            version:       buf.readUInt32LE(4),
            fileSizeBytes: fs.statSync(filePath).size,
        };
    } catch { return null; }
}

// Bounds keep the source scan fast on large repos: source files holding model
// refs are small; generated/vendored blobs are not worth reading.
const MAX_PY_FILES = 2000;
const MAX_PY_BYTES = 512 * 1024;   // 512 KB per file

// Reused across files to avoid per-file allocation in large repos.
const _scanBuf = Buffer.allocUnsafe(MAX_PY_BYTES);

/**
 * Scan Python source files for model ID strings.
 * Returns [{ modelId, sourceFile }] — deduplicated by modelId.
 *
 * Reads at most MAX_PY_BYTES per file with a single open/read/close (no separate
 * stat syscall) into a shared buffer — keeps the local scan fast on big repos.
 */
function scanPythonFilesForModelIds(pythonFiles) {
    const found = new Map();
    const files = pythonFiles.length > MAX_PY_FILES ? pythonFiles.slice(0, MAX_PY_FILES) : pythonFiles;
    for (const { path: fp } of files) {
        let src;
        try {
            const fd = fs.openSync(fp, 'r');
            try {
                const n = fs.readSync(fd, _scanBuf, 0, MAX_PY_BYTES, 0);
                src = _scanBuf.toString('utf8', 0, n);
            } finally {
                fs.closeSync(fd);
            }
        } catch { continue; }
        for (const re of MODEL_ID_REGEXPS) {
            re.lastIndex = 0;
            let m;
            while ((m = re.exec(src)) !== null) {
                const id = m[1].trim();
                if (id && !found.has(id)) found.set(id, fp);
            }
        }
    }
    return [...found.entries()].map(([modelId, sourceFile]) => ({ modelId, sourceFile }));
}

/**
 * Scan .env files for model name variables.
 * Returns [{ modelId, provider, sourceFile }].
 */
function scanEnvFilesForModels(envFiles) {
    const out = [];
    for (const { path: fp } of envFiles) {
        let src;
        try { src = fs.readFileSync(fp, 'utf8'); } catch { continue; }
        for (const { re, provider } of ENV_MODEL_VARS) {
            const m = re.exec(src);
            if (m) {
                const modelId = m[1].replace(/^["'\s]+|["'\s]+$/g, '').split('#')[0].trim();
                if (modelId) out.push({ modelId, provider, sourceFile: fp });
            }
        }
    }
    return out;
}

module.exports = {
    detectAIArtifacts,
    parseHFConfig,
    parseGGUFHeader,
    scanPythonFilesForModelIds,
    scanEnvFilesForModels,
    AI_PYTHON_PACKAGES,
};
