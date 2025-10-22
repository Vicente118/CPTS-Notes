## Authentication
In previous years (though we still see this sometimes during assessments), it was widespread for services to include default credentials (username and password).

Even when the service does not have a set of default credentials, an administrator may use weak passwords or no passwords when setting up services with the idea that they will change the password once the service is set up and running.

#### Anonymous Authentication
Another misconfiguration that can exist in common services is anonymous authentication. The service can be configured to allow anonymous authentication, allowing anyone with network connectivity to the service without being prompted for authentication.

#### Misconfigured Access Rights
Let's imagine we retrieved credentials for a user whose role is to upload files to the FTP server but was given the right to read every FTP document. The possibility is endless, depending on what is within the FTP Server.

## Unnecessary Defaults
The initial configuration of devices and software may include but is not limited to settings, features, files, and credentials. Those default values are usually aimed at usability rather than security. Leaving it default is not a good security practice for a production environment. Unnecessary defaults are those settings we need to change to secure a system by reducing its attack surface.

[Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) are part of the [OWASP Top 10 list](https://owasp.org/Top10/). Let's take a look at those related to default values:
- Unnecessary features are enabled or installed (e.g., unnecessary ports, services, pages, accounts, or privileges).
- Default accounts and their passwords are still enabled and unchanged.
- Error handling reveals stack traces or other overly informative error messages to users.
- For upgraded systems, the latest security features are disabled or not configured securely.
