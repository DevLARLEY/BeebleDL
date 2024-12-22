# BeebleDL
Downloads files from Beeble Could Storage

# Usage
```python
URL = "https://mail.beeble.com/share/........#............"

beeble = Beeble(URL)
password, file_hash, file_name = beeble.get_metadata()
beeble.download_and_decrypt(file_hash, password, file_name)
```
