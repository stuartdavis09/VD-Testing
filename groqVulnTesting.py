from groq import Groq
from cwe import Database

db = Database()
API_key = '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'
client = Groq(api_key= API_key)




# INPUTS

file_path = r"SecLLMHolmes\datasets\real-world\{0}\CVE-2023-{1}\{2}.c".format(model, testingCode, patchStatus)



promptTechnique = input("what prompt technique would you like to run it through? (D1-D5) ")
cweTested = int(input("what CWE index is being tested for? "))
###############################################################





# SAMPLES
vulnSamples = [
    r"\SecLLMHolmes\datasets\hand-crafted\dataset\CWE-{0}\1.c".format(cweTested),
    r"\SecLLMHolmes\datasets\hand-crafted\dataset\CWE-{0}\2.c".format(cweTested),
    r"\SecLLMHolmes\datasets\hand-crafted\dataset\CWE-{0}\3.c".format(cweTested),
   ]
for idx in range(len(vulnSamples)):
    with open(vulnSamples[idx], "r") as file:
        vulnSamples[idx] = file.read()
    

patchedSamples = [
    r"\SecLLMHolmes\datasets\hand-crafted\dataset\CWE-{0}\p_1.c".format(cweTested),
    r"\SecLLMHolmes\datasets\hand-crafted\dataset\CWE-{0}\p_2.c".format(cweTested),
    r"\SecLLMHolmes\datasets\hand-crafted\dataset\CWE-{0}\p_3.c".format(cweTested),
   ]
for idx in range(len(patchedSamples)):
    with open(patchedSamples[idx], "r") as file:
        patchedSamples[idx] = file.read()
##########################################







# PROMPT CREATION
vuln = db.get(cweTested)
vulnName = vuln.name
vulnDesc = vuln.description
promptTemplate = "Does the following code contain a vulnerability (YES/NO)? Include an explanation in the response."

if promptTechnique == "D4":
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
            "content" : prompts[promptTechnique],
        },
        {
            "role" : "user",
            "content" : promptTemplate + code
        }
    ],

    model="mixtral-8x7b-32768",
    temperature = 0
)

dataStore = open("Results\CWE-{0}-{1}-testing.txt".format(cweTested, promptTechnique), "x")
dataStore.write(chat_completion.choices[0].message.content)


print("----------COMPLETED security check-----------")