This is an install guide for people who want to simplicity, this will involve installing it into your root directory, and will be one copy paste (to install)

To install the script, copy and paste the following into your terminal:
If you have git use this:
```Posix shell
cd #changes directory to your root directory
git clone https://github.com/DavidMBeetle/sdig
cd ~/sdig #moves into your sdig directory
python3 -m venv sdigVirtrualEnvironment #creates virtrual environment for sdig
source sdigVirtrualEnvironment/bin/activate #load into your virtrual environment
pip3 install -r requirements.txt
deactivate
```

If you do not have access to git you can use this instead
```Posix shell
cd
curl -L https://github.com/DavidMBeetle/sdig/archive/refs/heads/main.zip --output sdig.zip #using curl with redirects
unzip sdig.zip #unzips it into the main folder
rm sdig.zip #removes the old zip file
mv sdig-main sdig
cd ~/sdig
python3 -m venv sdigVirtrualEnvironment #creates virtrual environment for sdig
source sdigVirtrualEnvironment/bin/activate #load into your virtrual environment
pip3 install -r requirements.txt
deactivate
```

To activate it or use it run
```Posix shell
cd ~/sdig
source ~/sdig/sdig/sdigVirtrualEnvironment/bin/activate
python3 sdig.py -h
```
