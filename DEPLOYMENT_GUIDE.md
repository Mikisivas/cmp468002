# Deployment Guide: One Project per Computer

Each of the 20 project folders is self-contained. A folder needs nothing from the rest of the repository, so you
copy one folder to one computer and run it there.

## 1. Get the files (once, on any computer with internet)

1. Open https://github.com/Mikisivas/cmp468002 and switch to branch `claude/zen-hypatia-vi77nb`.
2. Click **Code > Download ZIP** and unzip it.
3. Copy each project folder you need to a USB stick, for example:
   - `backup-recovery/A01-abu-zaria-zariasafe` for computer 1
   - `backup-recovery/A02-unn-nsukka-lionkeep` for computer 2
   - ... and so on up to `conflict-early-warning/B10-kogi-confluence`.

## 2. Set up each computer (about 10 minutes each)

Do this on every computer, with that computer's own folder:

1. Install Python 3.10 or newer from https://www.python.org/downloads/ . On the first installer screen tick
   **Add python.exe to PATH**.
2. Copy the project folder to `C:\CMP468\` (for example `C:\CMP468\A05-uniben-beninvault`).
3. Double-click **1_SETUP.bat**. It needs internet once, to download the Python packages.
4. Double-click **2_START.bat**. The browser opens the system. Keep the black window open.
5. Double-click **4_SELFTEST.bat** to prove the system works on that computer. Then run **1_SETUP.bat** again
   to get fresh demo data for the defence.
6. Use **3_DEMO_MENU.bat** during the presentation.

Login details for each system are at the top of its README.md.

### Computers without internet

On a computer with internet, open a terminal in the project folder and run:

```
python -m pip download -r requirements.txt -d wheels
```

Copy the folder (now including `wheels`) to the offline computer and install with:

```
python -m venv venv
venv\Scripts\activate
python -m pip install --no-index --find-links wheels -r requirements.txt
python main.py setup
```

Then use 2_START.bat as usual. `B10-kogi-confluence` needs no packages at all.

### Notes for Windows

- Windows Defender or another antivirus may warn about the ransomware simulation (`attack`, `stealth`). It only
  touches the demo folder inside the project. If it is blocked, allow the project folder, or skip that step.
- The map in B01, B04 and B09 loads street tiles from the internet. Without internet the coloured layers still draw.
  B02 PlateauWatch needs no internet at all.
- Every project has its own port (5101 to 5110, 5201 to 5210), so you can also run several projects on one computer.

## 3. Projects that use several computers together

Most projects run fully on one computer. Three are designed to span computers on the same network (LAN or Wi-Fi).
First find the main computer's IP address: open Command Prompt, type `ipconfig`, read the IPv4 Address
(for example `192.168.0.10`).

### A04 IfeSentinel (one console, many protected computers)

On the main computer:
1. In `config.json` set `"server_bind": "0.0.0.0"` and `"server_url": "http://192.168.0.10:5104"`.
2. Allow port 5104 in Windows Firewall (Windows Security > Firewall > Advanced settings > Inbound Rules > New Rule > Port > TCP 5104).
3. Run 1_SETUP.bat, then start the console with `python main.py server-only`.
4. Create a token for each other computer: `python main.py token --location "Bursary PC 2"`.

On each other computer:
1. Copy the same project folder and run 1_SETUP.bat once (to install packages).
2. Enrol: `venv\Scripts\python agent.py enrol --name BURSARY-PC2 --server http://192.168.0.10:5104 --token THE-TOKEN --folder D:\Bursary`
3. Run: `venv\Scripts\python agent.py run --name BURSARY-PC2`

The computer appears as a card on the console. Test it by unplugging its network cable (it turns OFFLINE).

### B10 ConfluenceEWS (one hub, several field tablets or laptops)

On the hub computer:
1. In `config.json` set `"bind": "0.0.0.0"` and allow TCP port 5210 in the firewall.
2. Run 1_SETUP.bat, then 2_START.bat.
3. Register each field device:
   `python -c "import field; field.provision('KG-TAB-05', 'Officer name', 'Ankpa', 'http://192.168.0.10:5210')"`
   This creates `data\tablets\KG-TAB-05`.

On each field laptop:
1. Copy the project folder, including `data\tablets\KG-TAB-05`. No packages are needed.
2. Record reports with no network: `python field.py add --device KG-TAB-05 --lga Ankpa --type threat --severity 2 --note "..."`
3. When connected: `python field.py sync --device KG-TAB-05`, then `python field.py show --device KG-TAB-05`.

### B01, B03, B04 (devices sending data to a central server)

These run on one computer, but data can come from other computers:
- B01 collars and B04 collars post signed positions to `/api/ping`.
- B03 receives SMS from a gateway at `/sms/inbound`.

To accept them from other machines, change `host="127.0.0.1"` to `host="0.0.0.0"` in the `serve()` function of
`app.py`, open the port in the firewall, and point the sender (`main.py simulate` or `main.py demo-feed`) at the
server's IP address.

## 4. Suggested allocation for a class of 20 students

| Computer | Project | Report |
|---|---|---|
| 1 to 10 | A01 to A10 (backup and recovery) | reports/A01 ... A10 |
| 11 to 20 | B01 to B10 (conflict early warning) | reports/B01 ... B10 |

Each student keeps one folder and one report. They should run 4_SELFTEST.bat on their own computer and, if
any number differs, rebuild their report (`pip install python-docx matplotlib`, then
`python reports/build/build_reports.py A05`) so Chapter Four matches their machine.

## 5. Before real (non-demo) use

- Put the web console behind HTTPS with a certificate.
- Replace demo passwords (`ChangeMe@468`) and set the secret and passphrase environment variables named in each config.json.
- Replace synthetic data with real records, official boundaries and verified incident data.
