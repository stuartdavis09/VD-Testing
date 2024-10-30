from groq import Groq

with open ("API_key.txt", "r") as file:
    for line in file:
        API_key = line
client = Groq(api_key= API_key)


inputs = {}
with open (r"Difference Detection\differenceDetectionTestingInfo.txt", "r") as file:
    for line in file:
        lineList = line.split(' - ')
        
        inputs[lineList[0]] = lineList[1].removesuffix("\n")


vuln_file = r".\SecLLMHolmes\datasets\real-world\{0}\CVE-2023-{1}\vuln.c".format(inputs["testingDataset"], inputs["testingCodeNumber"])
with open(vuln_file, "r") as file:
    vuln_file = file.read()

patch_file = r".\SecLLMHolmes\datasets\real-world\{0}\CVE-2023-{1}\patch.c".format(inputs["testingDataset"], inputs["testingCodeNumber"])
with open(patch_file, "r") as file:
    patch_file = file.read()


systemPrompt = "You are my assistant tasked to point out the textual difference between two sets of code\n\nLet's think Step-by-Step."

userPrompt = "This is the first set of code:\n{0}\n\nThis is the second set of code:\n{1}\n\n1. Are there any differences between the two sets of code?\n2. If there is a difference, cite the difference and 3. what does the difference mean to the code?\n\nGive your answer in the following structure:\n1.Yes, the codes are different/No, the codes aren't different\n2. Difference: ...\n3. Explanation: ...".format(vuln_file, patch_file)


chat_completion = client.chat.completions.create(
    messages= [
        {
            "role" : "system",
            "content" : systemPrompt,
        },
        {
            "role": "user",
            "content": userPrompt,
        }
    ],
    model=inputs["model"],
    temperature=0.5
)

dataStore = open("Difference Detection\DifferenceDetectionResults\{0}\CWE-2023-{1}-diffTest.txt".format(inputs["testingDataset"], inputs["testingCodeNumber"]), "x")
dataStore.write(chat_completion.choices[0].message.content)

dataStorePrompt = open("Difference Detection\DifferenceDetectionResults\{0}\{1}-prompt.txt".format(inputs["testingDataset"], inputs["testingCodeNumber"]), "x")
dataStorePrompt.write(systemPrompt + "\n\n\n" + userPrompt)