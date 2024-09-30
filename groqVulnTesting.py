from groq import Groq
from cwe import Database

db = Database()

with open ("API_key.txt", "r") as file:
    for line in file:
        API_key = line

print(API_key)
client = Groq(api_key= API_key)




# INPUTS
inputs = {}
with open (r"testingInfo.txt", "r") as file:
    for line in file:
        lineList = line.split(' - ')
        
        inputs[lineList[0]] = lineList[1].removesuffix("\n")





file_path = r"SecLLMHolmes\datasets\real-world\{0}\CVE-2023-{1}\{2}.c".format(inputs["testingModel"], inputs["testingCodeNumber"], inputs["patchStatus"])
###############################################################





# SAMPLES
vulnSamples = [
    r"SecLLMHolmes\datasets\hand-crafted\dataset\CWE-{0}\1.c".format(inputs["cweTested"]),
    r"SecLLMHolmes\datasets\hand-crafted\dataset\CWE-{0}\2.c".format(inputs["cweTested"]),
    r"SecLLMHolmes\datasets\hand-crafted\dataset\CWE-{0}\3.c".format(inputs["cweTested"]),
   ]
for idx in range(len(vulnSamples)):
    print(vulnSamples[idx])
    with open(vulnSamples[idx], "r") as file:
        vulnSamples[idx] = file.read()
    

patchedSamples = [
    r"SecLLMHolmes\datasets\hand-crafted\dataset\CWE-{0}\p_1.c".format(inputs["cweTested"]),
    r"SecLLMHolmes\datasets\hand-crafted\dataset\CWE-{0}\p_2.c".format(inputs["cweTested"]),
    r"SecLLMHolmes\datasets\hand-crafted\dataset\CWE-{0}\p_3.c".format(inputs["cweTested"]),
   ]
for idx in range(len(patchedSamples)):
    with open(patchedSamples[idx], "r") as file:
        patchedSamples[idx] = file.read()
##########################################







# PROMPT CREATION
vuln = db.get(inputs["cweTested"])
vulnName = vuln.name
vulnDesc = vuln.description
promptTemplate = "Does the following code contain a vulnerability (YES/NO)? Include an explanation in the response."

if inputs["promptingTechnique"] == "D4":
    promptTemplate += " Please explain in step-by-step format.\n"
else:
    promptTemplate += "\n"



prompts = {
    "D1": "A security vulnerability refers to: {0}.\n".format(vulnDesc),
    "D2": "You are a security expert analyzing for {0}, which refers to: {1}.\n".format(vulnName, vulnDesc),
    "D3": "You are a security expert analyzing for {0}, which refers to: {1}.\nSome examples of these vulnerabilities are shown in {2}.\nPatched versions of these code are shown in {3}.\n".format(vulnName, vulnDesc, vulnSamples, patchedSamples),
    "D4": "You are a security expert analyzing for {0}, which refers to: {1}.\nSome examples of these vulnerabilities are shown in {2}.\nPatched versions of these code are shown in {3}.\n".format(vulnName, vulnDesc, vulnSamples, patchedSamples),
    "D5": "A security vulnerability refers to: {0}.\nSome examples of these vulnerabilities are shown in {1}.\nPatched versions of these code are shown in {2}.\nInclude any given explanation in step-by-step format\n".format(vulnDesc, vulnSamples, patchedSamples),
}
############################################################






with open(file_path, "r") as file:
    code = file.read()


chat_completion = client.chat.completions.create(
    messages = [
        {
            "role" : "system",
            "content" : prompts[inputs["promptingTechnique"]],
        },
        {
            "role" : "user",
            "content" : promptTemplate + code
        }
    ],

    model="mixtral-8x7b-32768",
    temperature = 0
)

dataStore = open("Results\{0}\CWE-2023-{1}-{2}-{3}-testing.txt".format(inputs["testingModel"], inputs["testingCodeNumber"], inputs["promptingTechnique"], inputs["patchStatus"]), "x")
dataStore.write(chat_completion.choices[0].message.content)


print("----------COMPLETED security check-----------")