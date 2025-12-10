from ollama import chat, ChatResponse

response: ChatResponse = chat(model='gpt-oss:20b', messages=
    [
        {
            'role': 'user', 
            'content': 'Why is the sky blue?',
         }
     ])

print(response['message']['content']) 
print(response.message.content)
