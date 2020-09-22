'''
PREDICTION : Compasses through bot activity files and manual activity files 
             to get an idea about the differences in packet sizes between bot and manual activities
CUSTOM INPUT : Enter the path to manual directory : *enter the location to the directory in your local machine*
               Enter the path to bot directory : *enter the location to the directory in your local machine*
'''

import pyshark
import asyncio
import os

def main():
    #asking for input from the user 

    path1=input("Enter the path to manual directory : ")
    path2=input("Enter the path o bot directory : ")
    
    #extracting all manual files from manual directory

    l1=os.listdir(path1)

    #initialize two sets to store the unique tls segment length

    bot=set()
    manual=set()

    #iterating over the manual file list 

    for i in l1:

        f=open(path1+"/"+str(i),'r')
        cap=pyshark.FileCapture(f,only_summaries=False,display_filter='tls.record.content_type==23')
        
        for pkt in cap:
            try:
                manual.add(pkt.tls.record_length)
            except:
                continue

        f.close()

    print("The unique tls segment lengths collected from all the manual capture files are as below \n")
    Manual=list(manual)
    print(Manual)
    print("\n")

    #extracting all bot files from the bot directory


    l2=os.listdir(path2)
    #print(l2)

    #iterating over the bot file list

    for i in l2:
        
        f=open(path2+"/"+str(i),'r')
        cap=pyshark.FileCapture(f,only_summaries=False,display_filter='tls.record.content_type==23')
        
        for pkt in cap:
            try:
                bot.add(pkt.tls.record_length)
            except:
                continue
        f.close()

    print("The unique tls segment lengths collected from all the bot capture files are as below \n")
    Bot=list(bot)
    print(Bot)
    print("\n")

    #printing the similar segment lengths from both the directories
    print("The similar segment lengths from both types of capture files are as below \n")
    common=manual.intersection(bot)
    Common=list(common)
    print(Common)
    print("\n")

    print("The unique manual tls segments are\n")
    manual_unique=manual-(manual.intersection(bot))
    print(list(manual_unique))
    print("\n")

    print("The unique bot tls segments are\n")
    bot_unique=bot-(manual.intersection(bot))
    print(list(bot_unique))
    print("\n")

    #storing the data in a file 
    with open("bot_manual_data","w") as fhandle:
        fhandle.write("\n")
        for line in Manual:
            fhandle.write(line)
            fhandle.write(",")
        fhandle.write("\n")
        for line in Bot:
            fhandle.write(line)
            fhandle.write(",")
        fhandle.write("\n")
        for line in Common:
            fhandle.write(line)
            fhandle.write(",")
        fhandle.write("\n")

if __name__ == "__main__":
    #read()
    main()
    #dmain()


