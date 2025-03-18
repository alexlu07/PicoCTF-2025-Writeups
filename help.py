from os import *
for i in listdir():
    if len(i.split('.')) == 1:
        chdir(i)
        for j in listdir():
            chdir(j)
            try:
                rename(f"{j}.md", 'README.md')
                print(f"Renamed {getcwd()}/{j}.md to README.md")
            except:
                print(f"Failed to rename {getcwd()}/{j}.md to README.md")
            chdir('..')
        chdir('..')