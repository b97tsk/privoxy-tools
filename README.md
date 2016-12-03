# adblist-to-actionsfile
adblist-to-actionsfile converts AdBlock filters to actionsfile used by privoxy.
```
$ wget https://easylist-downloads.adblockplus.org/easylist.txt
$ cat easylist.txt | adblist-to-actionsfile >easylist.action
```

# gfwlist-to-actionsfile
gfwlist-to-actionsfile converts [gfwlist](https://github.com/gfwlist/gfwlist) to actionsfile used by privoxy.
```
$ wget https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt
$ cat gfwlist.txt | openssl enc -base64 -d | gfwlist-to-actionsfile >gfwlist.action
```
