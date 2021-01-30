# MWC Floonet (Testnet) Faucet

If you neeed some coins to test with MWC floonet, please be free to use the faucet that listen on MWC MQS address `xmgEvZ4MCCGMJnRnNXKHBbHmSGWQchNr9uZpY5J1XXnsCFS45fsU`.

Faucet is running is mwc713 wallet, so we recommend to use mwc713 wallet to request the coins. Then you can transafer them to your QT wallet or mwc-wallet. 

You can download mwc713 from here: https://github.com/mwcproject/mwc713/releases 

We are assuming that you already download, installed and provision your mwc713 wallet. Here are how you can request the coins. Please note, you can request maximun 5 MWC at a time.

### How to request the coins

```
> mwc713 --floonet
Using wallet configuration file at ......

Welcome to wallet713 for MWC v4.1.0

Unlock your existing wallet or type 'init' to initiate a new one
Use 'help' to see available commands

ERROR: The wallet is locked. Please use 'unlock' first.
wallet713>
wallet713> unlock -p XXXXXXXXXX
Your mwcmqs address: xmj6hXXXXXXXXXXXXX
wallet713>
wallet713> listen -s
Starting mwcmqs listener...
wallet713>
mwcmqs listener started for [xmj6hTX7UKAXXXXXXXXXXXXXX] tid=[kbxsjQ2TAo0jjLsl8Ib_L]

wallet713> invoice 1.5 --to xmgEvZ4MCCGMJnRnNXKHBbHmSGWQchNr9uZpY5J1XXnsCFS45fsU
slate [c7831053-80fb-4956-8abd-f2b270afc5ff] for [1.500000000] MWCs sent to [mwcmqs://xmgEvZ4MCCGMJnRnNXKHBbHmSGWQchNr9uZpY5J1XXnsCFS45fsU]
slate [c7831053-80fb-4956-8abd-f2b270afc5ff] received back from [xmgEvZ4MCCGMJnRnNXKHBbHmSGWQchNr9uZpY5J1XXnsCFS45fsU] for [1.500000000] MWCs
```

Please note, if faucet not used for a long time, it might take few minutes to wakeup and resync with a blockchain. If you invoice failed,
please wait for 10 minutes and try again. If it is still offline, please ping any moderator at Discord( https://discord.gg/n5dZaty ) 'developers' channel.  

### How to return the coin 

When you finish with your tests, please send the coins back to faucet. 
```
send 3.123 --to xmgEvZ4MCCGMJnRnNXKHBbHmSGWQchNr9uZpY5J1XXnsCFS45fsU -c 1
```