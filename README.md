# Cloudflare WAF Rules Automation Toolkit

This PowerShell toolkit, contained within the 'Cloudflare WAF Rules.ps1' script, empowers efficient Cloudflare Web Application Firewall (WAF) rule management. The toolkit utilizes the Cloudflare API, enhancing security and automation for your specified zones.

## Prerequisites
- **PowerShell 7:** Ensure you have PowerShell 7 installed on your system.
- **API Token:** Securely store your Cloudflare API token in an environment variable or a `.env` file.

## Setup
1. **Environment Variable:** Set your Cloudflare API token as an environment variable in a .env file. See .env.example.

2. **WAF Rules Expression:** Define WAF rules expressions in 'Cloudflare WAF Rules.json'. Refer to 'Cloudflare WAF Rules.json.example' as a template.

## Functionality

### 1. **WAF Rules Automation**
- **Function:** Automates Cloudflare Web Application Firewall (WAF) rule management for specified zones.
- **Usage:**
  ```powershell
  Set-ZoneWAFRule -RuleNames "Rule1", "Rule2" -Sites "example.com", "example2.com"  
  ```

  Calling the function without parameters will cause the function to get all zones available to the API token and/or synchronize all WAF rules defined in the JSON file.

### 2. **Zone Information Retrieval**
- **Function:** Retrieves essential information about specified Cloudflare zones, including zone ID, name, and default ruleset.
- **Usage:**
  ```powershell
  Get-Zones -Sites "example.com", "example2.com"
  ```

## WAF Rules Expression
The WAF rules expressions are sourced from 'Cloudflare WAF Rules.json'. Use 'Cloudflare WAF Rules.json.example' as a template for defining rules.

## Progress Bar Alternative
The toolkit provides a text-based progress bar alternative, `Show-Progress`, for consistent progress updates within loops. Example usage:
```powershell
Show-Progress -Activity "Getting Zone WAF Rules" -Status "Processing Zones" -CurrentOperation "Zone: $($ZoneObject.name)" -PercentComplete $ProgressPercent
```

## Security Considerations
- **Secure API Tokens:** Ensure robust storage of API tokens and sensitive data. Avoid hardcoded information in scripts. Employ environment variables or secure credential storage methods.

## Feedback and Contributions
Feedback, issues, and contributions are welcome. Feel free to create GitHub issues or pull requests for suggestions and improvements.

---

*Note: Properly securing API tokens and sensitive data is crucial. While this toolkit offers best practice guidance, it's essential to consider all security aspects in your implementation.*