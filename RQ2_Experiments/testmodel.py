from g4f.client import Client
import json

client = Client()

models = [
    # OpenAI
    'gpt-4o', 'gpt-4', 'gpt-4o-mini', 'gpt-3.5-turbo-1106',

    # Anthropic Claude
    'claude-3.5-sonnet', 'claude-3-sonnet', 'claude-3-opus', 'claude-2',
    'claude-instant', 'claude-instant-1.2', 'claude-3-haiku', 'claude-3.7-sonnet',

    # Google DeepMind
    'gemini-1.5-pro', 'gemini-1.5-flash', 'gemini-1.0-pro', 'palm-2',

    # Meta LLaMA
    'llama-3.1-405b', 'llama-3.1-70b', 'llama-3.1-8b',
    'llama-2-70b', 'llama-2-13b', 'llama-2-7b', 'llama-3-8b', 'llama-3-70b',

    # Mistral
    'mistral-7b', 'mixtral-8x7b', 'mistral-large', 'mistral-medium', 'mistral-small',

    # Cohere
    'command', 'command-light', 'command-nightly',
    'command-r', 'command-r-plus',

    # Qwen / Yi / DeepSeek
    'qwen-14b', 'qwen-7b', 'yi-34b', 'yi-6b', 'deepseek-coder',

    # Others
    'j2-ultra', 'j2-mid', 'blackboxai', 'blackboxai-pro'
]

print("🔍 Starting availability check for all models...\n")

available_models = []
unavailable_models = []

for model in models:
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "Testing availability"}],
            timeout=60
        ).choices[0].message.content.strip()
        print(f"✅ Model '{model}' is available. Response: {response}")
        available_models.append(model)
    except Exception as e:
        print(f"❌ Model '{model}' is not available. Error: {e}")
        unavailable_models.append(model)

print("\n==================== SUMMARY ====================")
print(f"✅ Available models ({len(available_models)}):")
for m in available_models:
    print(f"  - {m}")

print(f"\n❌ Unavailable models ({len(unavailable_models)}):")
for m in unavailable_models:
    print(f"  - {m}")

# Optional: Save results to JSON files
with open("available_models.json", "w") as f:
    json.dump(available_models, f, indent=2)

with open("unavailable_models.json", "w") as f:
    json.dump(unavailable_models, f, indent=2)

print("\n📁 Results saved to 'available_models.json' and 'unavailable_models.json'")
