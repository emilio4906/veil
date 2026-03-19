# Using Veil with the OpenAI SDK

When running the Veil client proxy, you can use the standard OpenAI SDK unchanged.
Just point it at your local Veil proxy:

```python
from openai import OpenAI

# Point at local Veil proxy instead of api.openai.com
client = OpenAI(
    base_url="http://localhost:8480/v1",
    api_key="your-api-key",  # passed through in headers
)

response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "What is quantum computing?"}],
)

print(response.choices[0].message.content)
```

The Veil proxy transparently encrypts your prompt before it leaves your machine
and decrypts the response when it comes back. The OpenAI SDK never knows the
difference.
