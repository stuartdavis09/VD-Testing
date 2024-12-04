from groq import Groq
from cwe import Database
import time

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

dataset = {
    "gpac": {
        "1452":"787",
        "3012":"476",
        "23143":"787",
        "23144":"190"
    },
    "libtiff": {
        "2908":"476",
        "3316":"476",
        "26966":"787",
        "40745":"190",
        "41175":"190"
    },
    "linux": {
        "40283":"416",
        "42753":"190",
        "42754":"476",
        "45863":"787",
        "45871":"787"
    },
    "pjsip": {
        "27585":"787"
    }
}




# INPUTS
inputs = {
    "testingDataset":"",
    "testingCodeNumber":"",
    "patchStatus":"",
    "cweTested":"",
    "promptingTechnique":"",
    "model":""

}
with open (r"vulnTestingInfo.txt", "r") as file:
    for line in file:
        lineList = line.split(' - ')
        
        inputs[lineList[0]] = lineList[1].removesuffix("\n")

print(inputs)






def savePrompt(systemPrompt, userPrompt, resultName):
    if (inputs["promptingTechnique"] == "SD1" or inputs["promptingTechnique"] == "SD2" or inputs["promptingTechnique"] == "SD3" or inputs["promptingTechnique"] == "SD4" or inputs["promptingTechnique"] == "SD5"):
        resultName = "Results"


    elif inputs["promptingTechnique"] == "D1" or inputs["promptingTechnique"] == "D2" or inputs["promptingTechnique"] == "D3" or inputs["promptingTechnique"] == "D4" or inputs["promptingTechnique"] == "D5":
        resultName = "ResultsSecLLMHolmesPrompts"


    elif inputs["promptingTechnique"] == "cwe-df":
        resultName = "ResultsCWE-df"


    elif inputs["promptingTechnique"] == "OP":
        resultName = "ResultsOP"


    dataStore = open("{0}\{1}\{2}\{3}\Prompts\{4}-{5}-{6}-PROMPT.txt".format(inputs["model"], inputs["dataset"], resultName, inputs["testingDataset"], inputs["testingCodeNumber"], inputs["promptingTechnique"], inputs["patchStatus"]), "x")
    dataStore.write("System:\n" + systemPrompt + "\n\n\nUser:\n" + userPrompt)















def chatBot():




    if inputs["dataset"] == "FunctionOnlyDataset":
        file_path = r"FunctionOnlyDataset\{0}\CVE-2023-{1}\{2}.c".format(inputs["testingDataset"], inputs["testingCodeNumber"], inputs["patchStatus"])
    elif inputs["dataset"] == "SecLLMHolmesDataset":
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

    elif inputs["promptingTechnique"] == "cwe-df":
        promptTemplate = " Is the following code snippet prone to {0}\n{1}?".format(vulnName, code)

    elif inputs["promptingTechnique"] == "OP" or inputs["promptingTechnique"] == "OP-FS":
        promptTemplate = "Please analyze the following code for {0}:\n\n--------------- START OF CODE ---------------\n{1}\n--------------- END OF CODE ---------------\n\nCarefully analyze the given code snippet and track the data flows from various sources to sinks. Assume that any call to an unknown external API is unsanitized.".format(vulnName, code)
        


    prompts = {
        "SD1": "A security vulnerability refers to: {0}.\n".format(vulnDesc),
        "SD2": "You are a security expert that is good at {0} analysis, which refers to {1}.\n".format(vulnName, vulnDesc),
        "SD3": "You are a security expert that is good at {0} analysis, which refers to {1}.\nSome vulnerable exemplars are shown in {2}.\nPatched versions of these are shown in {3}.\n".format(vulnName, vulnDesc, vulnSamples, patchedSamples),
        "SD4": "You are a security expert that is good at {0} analysis, which refers to: {1}.\nSome vulnerable exemplars are shown in {2}.\nPatched versions of these are shown in {3}.\n".format(vulnName, vulnDesc, vulnSamples, patchedSamples),
        "SD5": "A security vulnerability refers to: {0}.\nSome vulnerable exemplars are shown in {1}.\nPatched versions of these are shown in {2}.\n".format(vulnDesc, vulnSamples, patchedSamples),



        "D1": "Does this code contain instances of the security vulnerability known as {0}.\n".format(vulnName),
        "D2": "You are a code security expert who analyzes the given code for the security vulnerability known as {0}.\n\n{1}\n".format(vulnName, vulnDesc),
        "D3": "You are a code security expert who analyzes the given code for the security vulnerability known as {0}.\n\n{1}\n\n{2}\n\n{3}\n".format(vulnName, vulnDesc, vulnSamples, patchedSamples),
        "D4": "You are a code security expert who analyzes the given code for the security vulnerability known as {0}.\n\n{1}\n\n{2}\n\n{3}\n".format(vulnName, vulnDesc, vulnSamples, patchedSamples),
        "D5": "Analyze the given code for the security vulnerability known as {0}.\n\n{1}\n\n{2}\n\n{3}\n".format(vulnName, vulnDesc, vulnSamples, patchedSamples),


        "cwe-df": "You are a security researcher, expert in detecting security vulnerabilities. Carefully analyze the given code snippet and track the data flows from various sources to sinks. Assume that any call to an unknown external API is unsanitized.\nPlease provide a response only in the following itemized OUTPUT FORMAT. Use N/A in other fields if there are no vulnerabilities. DO NOT INCLUDE ANYTHING ELSE IN YOUR RESPONSE.\n<OUTPUT FORMAT>\nData flow analysis of the given code snippet:\n1. Sources: <numbered list of input sources>\n2. Sinks: <numbered list of output sinks>\n3. Sanitizers: <numbered list of sanitizers, if any>\n4. Unsanitized Data Flows: <numbered list of data flows that are not sanitized in the format (source, sink, why this flow could be vulnerable)>\n5. Final Vulnerability analysis verdict: vulnerability: <YES or NO>\n| vulnerability type: {0} |\n| vulnerability name: {1}|\n| explanation: <explanation for prediction>|".format(inputs["cweTested"], vulnName),
    
        "OP": "You are a security expert in detecting {0}.\n{1}\nGive your answer in the following structure:\n1. Vulnerability analysis: <YES, THERE IS A VULNERABILITY or NO, THERE IS NO VULNERABILITY>\n2. Explanation: <Leave as N/A if there is no vulnerability>\n| CWE Name: <Name of Vulnerability> |".format(vulnName, vulnDesc),
        "OP-FS": "You are a security expert in detecting {0}.\n{1}\nThis is an example of vulnerable code:\n----VULNERABLE CODE START-----\n{2}\n-----VULNERABLE CODE END-----\n\n-----EXPLANATION OF VULNERABILITY-----\n{3}\n-----EXPLANATION END-----\n\nThis is an example of patched code:\n-----PATCHED CODE START-----\n{4}\n-----PATCHED CODE END-----\n\n-----EXPLANATION OF PATCH-----\n{5}\n-----EXPLANATION END-----\n\n\nGive your answer in the following structure:\n1. Vulnerability analysis: <YES, THERE IS A VULNERABILITY or NO, THERE IS NO VULNERABILITY>\n2. Explanation: <Leave as N/A if there is no vulnerability>\n| CWE Name: <Name of Vulnerability> |".format(vulnName, vulnDesc, vulnSamples[0], vulnSamples[1], patchedSamples[0], patchedSamples[1])
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
            },
        ],

        model=inputs["model"],
        temperature = 0.5
    )

    if (inputs["promptingTechnique"] == "SD1" or inputs["promptingTechnique"] == "SD2" or inputs["promptingTechnique"] == "SD3" or inputs["promptingTechnique"] == "SD4" or inputs["promptingTechnique"] == "SD5"):
        resultName = "Results"



    elif inputs["promptingTechnique"] == "D1" or inputs["promptingTechnique"] == "D2" or inputs["promptingTechnique"] == "D3" or inputs["promptingTechnique"] == "D4" or inputs["promptingTechnique"] == "D5":
        resultName = "ResultsSecLLMHolmesPrompts"


    elif inputs["promptingTechnique"] == "cwe-df":
        resultName = "ResultsCWE-df"


    elif inputs["promptingTechnique"] == "OP":
        resultName = "ResultsOP"
    
    elif inputs["promptingTechnique"] == "OP-FS":
        resultName = "ResultsOP-FS"



    dataStore = open("{0}\{1}\{2}\{3}\CWE-2023-{4}-{5}-{6}-testing.txt".format(inputs["model"], inputs["dataset"], resultName, inputs["testingDataset"], inputs["testingCodeNumber"], inputs["promptingTechnique"], inputs["patchStatus"]), "x")
    dataStore.write(chat_completion.choices[0].message.content)

    savePrompt(prompts[inputs["promptingTechnique"]], promptTemplate, resultName)

    

    print("----------COMPLETED security check-----------")















for testingDataset in dataset.keys():
    inputs["testingDataset"] = testingDataset
    for testingCodeNumber in dataset[testingDataset].keys():
        inputs["testingCodeNumber"] = testingCodeNumber
        inputs["cweTested"] = dataset[testingDataset][testingCodeNumber]

        inputs["patchStatus"] = "patch"
        chatBot()
        time.sleep(7.0)

        inputs["patchStatus"] = "vuln"
        chatBot()
        time.sleep(7.0)

print("\n\n\n------- ALL IS DONE! --------")