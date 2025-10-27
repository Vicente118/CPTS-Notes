The attack involves attempting to log into an exposed service using one common password and a longer list of usernames or email addresses.

#### Password Spray Visualization
| **Attack** | **Username**                  | **Password** |
| ---------- | ----------------------------- | ------------ |
| 1          | bob.smith@inlanefreight.local | Welcome1     |
| 1          | john.doe@inlanefreight.local  | Welcome1     |
| 1          | jane.doe@inlanefreight.local  | Welcome1     |
| DELAY      |                               |              |
| 2          | bob.smith@inlanefreight.local | Passw0rd     |
| 2          | john.doe@inlanefreight.local  | Passw0rd     |
| 2          | jane.doe@inlanefreight.local  | Passw0rd     |
| DELAY      |                               |              |
| 3          | bob.smith@inlanefreight.local | Winter2022   |
| 3          | john.doe@inlanefreight.local  | Winter2022   |
| 3          | jane.doe@inlanefreight.local  | Winter2022   |