During installation and use, it's highly recommended you use a virtual environment.

To start, cd into any folder you want to built this in, keep in mind that it will build a folder for you in that folder.

Keep in mind that this program is made for macOS/Linux, it should work on all unix based or unix like operating systems.
This program was not built

Second note, you will need python to do this. This was build using python 3.14.5.

Steps:

1.
```Posix Shell
git clone https://github.com/DavidMBeetle/sdig
```

2.
After that cd into the folder
```Posix Shell
cd sdig
```

3. 
The following step is recommended but not required. It is highly recommended though. This is to build a virtrual environment to install depedencies into
```shell python
python3 -m venv sdigVirtrualEnvironment
```

4. 
Load into your virtrual environment
```Posix Shell
source sdigVirtrualEnvironment/bin/activate
```

5. 
The following installs all of the listed dependencies in the requirements.txt file.
```shell python
pip3 install -r requirements.txt
```

6. 
For all macOS users, in order for the program to work, u need to run the python given install certs script. You can do it like so:

```Posix Shell
open /Applications/Python\ 3.14/Install\ Certificates.command
```

You need to do this because it uses TLS certs and the pythonssl library doesn't come with given certs and neither does macOS (some operating systems do i believe)
Because of that you cannot make TLS connections without the certs which is why you have to run that. Anyhow, on to the next step.

Now then, how to use it for daily life:

Steps for daily use:

1.

Now then, to be able to use it in a daily life or new instance you have to do the following. First change directory into your sdig file.
If it's in home directory then it would be

```Posix Shell
cd ~/sdig
```

2. Ensure that you copied the config file into your folder and that you like the settings (customizing it is advanced, you can keep defaults and it'll work fine)

```Posix shell
ls
open config.toml
```

4. 
Then you need to load into your virtrual environment each time you use it.
```zsh
source sdigVirtrualEnvironment/bin/activate
```

4. Run the program like so:
```Shell python
python3 sdig.py -h
```

That will give you the help message and that should explain how to use it.


