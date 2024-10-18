from groq import Groq
from cwe import Database

db = Database()

with open ("API_key.txt", "r") as file:
    for line in file:
        API_key = line
client = Groq(api_key= API_key)






vulnLang = {
    "22": "c",
    "77": "c",
    "79": "py",
    "89": "py",
    "190": "c",
    "416": "c",
    "476": "c",
    "787": "c"
}




# INPUTS
inputs = {}
with open (r"testingInfo.txt", "r") as file:
    for line in file:
        lineList = line.split(' - ')
        
        inputs[lineList[0]] = lineList[1].removesuffix("\n")





file_path = r"SecLLMHolmes\datasets\real-world\{0}\CVE-2023-{1}\{2}.c".format(inputs["testingDataset"], inputs["testingCodeNumber"], inputs["patchStatus"])
###############################################################
with open(file_path, "r") as file:
    code = file.read()




if (inputs["promptingTechnique"] == "D4" or inputs["promptingTechnique"] == "D5"):
    reasoningMethod = "step-by-step-"
else:
    reasoningMethod = ""


# SAMPLES
vulnSamples = [
    r"SecLLMHolmes\datasets\few-shot\examples\cwe-{0}.{1}".format(inputs["cweTested"], vulnLang[inputs["cweTested"]]),
    r"SecLLMHolmes\datasets\few-shot\{0}reasoning\cwe-{1}.txt".format(reasoningMethod, inputs["cweTested"])
]
for idx in range(len(vulnSamples)):
    print(vulnSamples[idx])
    with open(vulnSamples[idx], "r") as file:
        vulnSamples[idx] = file.read()
    

patchedSamples = [
    r"SecLLMHolmes\datasets\few-shot\examples\cwe-{0}-p.{1}".format(inputs["cweTested"], vulnLang[inputs["cweTested"]]),
    r"SecLLMHolmes\datasets\few-shot\{0}reasoning\cwe-{1}-p.txt".format(reasoningMethod, inputs["cweTested"])
]
for idx in range(len(patchedSamples)):
    with open(patchedSamples[idx], "r") as file:
        patchedSamples[idx] = file.read()
##########################################







# PROMPT CREATION
vuln = db.get(inputs["cweTested"])
vulnName = vuln.name
vulnDesc = vuln.description
promptTemplate = "Please analyze the following code and give an explanation:\n{0}\nPlease indicate your analysis with one of the options:\n (1) YES: a security vulnerability is detected\n (2) NO: no security vulnerability detected\n Give your answer in the given format:\nAnswer: ... (based off the options above)\n Explanation: ...".format(code)

if inputs["promptingTechnique"] == "D4" or inputs["promptingTechnique"] == "D5":
    promptTemplate += "Let's think step-by-step.\n"



# prompts = {
#     "D1": "A security vulnerability refers to: {0}.\n".format(vulnDesc),
#     "D2": "You are a security expert that is good at {0} analysis, which refers to {1}.\n".format(vulnName, vulnDesc),
#     "D3": "You are a security expert that is good at {0} analysis, which refers to {1}.\nSome vulnerable exemplars are shown in {2}.\nPatched versions of these are shown in {3}.\n".format(vulnName, vulnDesc, vulnSamples, patchedSamples),
#     "D4": "You are a security expert that is good at {0} analysis, which refers to: {1}.\nSome vulnerable exemplars are shown in {2}.\nPatched versions of these are shown in {3}.\n".format(vulnName, vulnDesc, vulnSamples, patchedSamples),
#     "D5": "A security vulnerability refers to: {0}.\nSome vulnerable exemplars are shown in {1}.\nPatched versions of these are shown in {2}.\n".format(vulnDesc, vulnSamples, patchedSamples),
# }


prompts = {
    "D1": "Does this code contain instances of the security vulnerability known as {0}.\n".format(vulnName),
    "D2": "You are a code security expert who analyzes the given code for the security vulnerability known as {0}.\n\n{1}\n".format(vulnName, vulnDesc),
    "D3": "You are a code security expert who analyzes the given code for the security vulnerability known as {0}.\n\n{1}\n\n{2}\n\n{3}\n".format(vulnName, vulnDesc, vulnSamples, patchedSamples),
    "D4": "You are a code security expert who analyzes the given code for the security vulnerability known as {0}.\n\n{1}\n\n{2}\n\n{3}\n".format(vulnName, vulnDesc, vulnSamples, patchedSamples),
    "D5": "Analyze the given code for the security vulnerability known as {0}.\n\n{1}\n\n{2}\n\n{3}\n".format(vulnName, vulnDesc, vulnSamples, patchedSamples),
}
############################################################






chat_completion = client.chat.completions.create(
    messages = [
        {
            "role" : "system",
            "content" : prompts[inputs["promptingTechnique"]],
        },
        {
            "role" : "user",
            "content" : promptTemplate,
        }
    ],

    model=inputs["model"],
    temperature = 0.5
)

dataStore = open("ResultsOriginalPrompts\{0}\CWE-2023-{1}-{2}-{3}-testing.txt".format(inputs["testingDataset"], inputs["testingCodeNumber"], inputs["promptingTechnique"], inputs["patchStatus"]), "x")
dataStore.write(chat_completion.choices[0].message.content)


print("----------COMPLETED security check-----------")