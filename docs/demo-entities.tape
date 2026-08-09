Output "/tmp/releaseguard-demo/docs/demo-entities.gif"
Set FontSize 16
Set Width 760
Set Height 260
Set Theme "Dracula"
Set WindowBar Colorful
Set WindowBarSize 36

Type "export PS1='$ '"
Enter
Sleep 300ms

Type "export PATH=/tmp/releaseguard-demo/.venv/bin:$PATH"
Enter
Sleep 300ms

Type "clear"
Enter
Sleep 300ms

Type "releaseguard scan demo-sample --entities EMAIL_ADDRESS,PERSON,PHONE_NUMBER --json"
Enter
Sleep 5s
