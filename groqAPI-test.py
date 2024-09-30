from groq import Groq
import os 

with open ("API_key.txt", "r") as file:
    for line in file:
        API_key = line

client = Groq(api_key= API_key)

chat_completion = client.chat.completions.create(
    messages = [
        {
            "role": "system",
            "content": "include an explanation in the response to the user's question"

            # context
        },
        {
            "role": "user",
            # • system: provide instructions or context to the model- background information, define the task or topic, or give instructions to the model.
            # • user: message from a user or a customer - user's input or question.
            # • assistant: message from the assistant or the AI model. It's like the response from the model.


            "content": "Name the best Italian restaurant in Jakarta",
            # user input
            
        }
    ],
    model="mixtral-8x7b-32768",
)

print(chat_completion.choices[0].message.content)
# default temperature is at 0.5
# can see that answers vary/diversify everytime