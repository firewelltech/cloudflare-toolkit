# The Cloudflare (CF) API Token for this script's operations requires the following permissions:
# Zome: Read; Zone WAF: Edit

# Load environment variables from the .env file
$envConfigFile = ".\.env"
$envConfig = Get-Content -Path $envConfigFile | ForEach-Object { $_ }

# Set environment variables
foreach ($line in $envConfig) {
    if ($line -match '^\s*#|^\s*$') {
        # Skip comments and blank lines
        continue
    }
    $key, $value = $line.Trim() -split '=', 2
    [System.Environment]::SetEnvironmentVariable($key, $value, [System.EnvironmentVariableTarget]::Process)
}

$Script:ApiToken = $env:CF_Zone_WAF
$Script:BaseURL = "https://api.cloudflare.com/client/v4"

class Zone {
    [string]$id
    [string]$name
    [string]$default_ruleset_id
    [object[]]$waf_rules
}

# Write-Progress frequently doesn't display correctly in foreach loops, so use this text-based alternative.
function Show-Progress {
    param (
        [string]$Activity,
        [string]$Status,
        [string]$CurrentOperation,
        [int]$PercentComplete
    )

    $ProgressMessage = "{0} - {1} - {2} - {3}%" -f $Activity, $Status, $CurrentOperation, $PercentComplete

    Write-Host $ProgressMessage
    [System.Console]::Out.Flush()
}

# Utility function to construct the API authorization headers
function Set-Header {
    param (
        [string]$ApiToken = $Script:ApiToken
    )
    $Headers = @{
        "Authorization" = "Bearer $ApiToken"
        "Content-type"  = "application/json"
    }
    return $Headers
}

function Get-Zones {
    param (
        [string]$ApiToken = $Script:ApiToken,
        [string[]]$Sites
    )
    # Set the headers amd URL for the API requests
    $Headers = Set-Header
    $ApiURL = "$Script:BaseURL/zones"

    # Get the zone objects
    $Response = Invoke-RestMethod `
        -Uri $ApiURL `
        -Headers $Headers `
        -Method Get
    
    if ($Sites) {
        # $Sites specified as an input parameter, so filter $Response accordingly
        $Response.result = $Response.result | Where-Object { $Sites -contains $_.name }
    }
    
    # Numbers for progress bar
    $TotalZones = $Response.result.Count
    $CurrentZone = 0
    
    # Create an array to store Zone objects
    $Zones = @()

    # Iterate through each zone
    foreach ($Zone in $Response.result) {
        # Increment for progress bar
        $CurrentZone ++
        $ProgressPercent = [math]::Round(($CurrentZone / $TotalZones) * 100)

        # Instantiate a new object based on the Zone class 
        $ZoneObject = New-Object Zone
        $ZoneObject.id = $Zone.id
        $ZoneObject.name = $Zone.name

        $ApiURL = "$Script:BaseURL/zones/$($Zone.id)/rulesets"

        
        # Get the rulesets for the current zone
        $Rulesets = Invoke-RestMethod `
            -Uri $ApiURL `
            -Headers $Headers `
            -Method Get

        # Free CF zones have 3 Cloudflare rulesets and one "default" ruleset which is where custom rulesets live    
        $DefaultRuleSet = $Rulesets.result | Where-Object { $_.name -eq "default" }

        if ($DefaultRuleSet) {
            # The default ruleset was found, so populate the Zone object with data
            $ZoneObject.default_ruleset_id = ($Rulesets.result | Where-Object { $_.name -eq "default" }).id

            $WAFRulesArray = @()

            # Now that we have the ruleset ID, we can get all of the rules in the ruleset
            $WAFRules = Invoke-RestMethod `
                -Uri "$ApiURL/$($ZoneObject.default_ruleset_id)" `
                -Headers $Headers `
                -Method Get

            # Put the rules in the array
            $WAFRulesArray = $WAFRules.result.rules

            # The API doesn't return the current position:index of the WAF, so iterate through each WAF and assign its current index programatically. This is necessary to be able to set the index programmatically in other functions.
            $Index = 0

            foreach ($Rule in $WAFRulesArray) {
                # Increment $Index because the first rule position in CF is 1, not 0
                $Index ++
                # Add the index property and value to the $Rule object
                $Rule | Add-Member -MemberType NoteProperty -Name "position" -Value (New-Object PSObject -Property @{
                        index = $Index
                    }) -Force
            }

            # Add the WAF rules to our object as an array
            $ZoneObject.waf_rules = $WAFRulesArray
        }

        # Add the current $Zone to the $ZoneObject
        $Zones += $ZoneObject

        Show-Progress -Activity "Getting Zone WAF Rules" -Status "Processing Zones" -CurrentOperation "Zone: $($ZoneObject.name)" -PercentComplete $ProgressPercent
    }
   
    return $Zones
}

function Set-ZoneWAFRule {
    param (
        [parameter(Mandatory = $true)]
        [string[]]$RuleNames,
        [string[]]$Sites,
        [string]$ApiToken = $Script:ApiToken,
        [string]$BaseURL = $Script:BaseURL
    )

    # Get the path to the JSON file
    $CurrentDirectory = Get-Location
    $LocalPath = $CurrentDirectory.Path
    $JsonRules = Get-Content -Path (Join-Path -Path $LocalPath -ChildPath "Cloudflare WAF Rules.json") | ConvertFrom-Json

    # Check if the JSON rules are found
    if ($null -eq $JsonRules) {
        Write-Host "Cannot find Cloudflare WAF Rules.json - aborting."
        return
    }

    # Get the zones from the CF account
    $MyZones = Get-Zones -Sites $Sites

    # Set the headers for the API request
    $Headers = Set-Header

    foreach ($Rule in $RuleNames) {
        # Find the target rule based on $RuleNames parameter
        $TargetRule = $JsonRules | Where-Object { $_.name -eq $Rule }

        # Check if $TargetRule is found
        if ($null -eq $TargetRule) {
            Write-Host "$Rule not found in 'Cloudflare WAF Rules.json' - aborting."
            return
        }

        #Create an empty array to store the existing rule
        $ExistingRule = @()

        # Loop through each zone, find the WAF rule matching $Rule, and patch it.
        foreach ($Zone in $MyZones) {
            $ExistingRule = $Zone.waf_rules | Where-Object { $_.description -eq $Rule }

            # Create a copy of $TargetRule
            $UpdatedTargetRule = $TargetRule | ConvertTo-Json | ConvertFrom-Json

            # Replace $TargetRule's {domain} with the Zone's actual domain name
            $UpdatedTargetRule.expression = $UpdatedTargetRule.expression -replace '{domain}', $Zone.name

            if ($null -eq $ExistingRule) {
                # Rule doesn't exist, so create it
                $NewRule = @{
                    description       = $Rule
                    action            = $UpdatedTargetRule.action
                    expression        = $UpdatedTargetRule.expression
                    enabled           = $UpdatedTargetRule.enabled
                    position          = $UpdatedTargetRule.position
                    action_parameters = $UpdatedTargetRule.action_parameters
                }

                $ApiURL = "$BaseURL/zones/$($Zone.id)/rulesets/$($Zone.default_ruleset_id)/rules"

                try {
                    Invoke-RestMethod `
                        -Headers $Headers `
                        -Uri $ApiURL `
                        -Method Post `
                        -Body ($NewRule | ConvertTo-Json) `
                        -ContentType 'application/json' `
                    | Out-Null
                    Write-Host "Rule '$($Rule)' not found at '$($Zone.name),' so we created it!"
                }
                catch {
                    Write-Host "Error occurred: $_"
                }
            }
            else {
                # The rule already exists, so patch it
                $ExistingRule.action = $UpdatedTargetRule.action
                $ExistingRule.expression = $UpdatedTargetRule.expression
                $ExistingRule.enabled = $UpdatedTargetRule.enabled
                if ($ExistingRule.action_parameters) {
                    # Only include action_parameters if the existing rule has the property
                    $ExistingRule.action_parameters = $UpdatedTargetRule.action_parameters
                }

                if ($ExistingRule.position.index -ne $UpdatedTargetRule.position.index) {
                    # The position of the existing and target rule doesn't match, so patch it. Submitting this property in the Patch request if the properites are equal will generate an error from the API.
                    $ExistingRule.position.index = $UpdatedTargetRule.position.index
                }
                else {
                    # The position of the existing and target rule is the same, so remove the index from the payload to avoid an API error (CF API won't accept the patch request if the requested index value isn't different)
                    $ExistingRule.PSObject.Properties.Remove('position')
                }

                $UpdatedRule = $ExistingRule | ConvertTo-Json
                
                $ApiURL = "$BaseURL/zones/$($Zone.id)/rulesets/$($Zone.default_ruleset_id)/rules/$($ExistingRule.id)"

                try {
                    Invoke-RestMethod `
                        -Uri $ApiURL `
                        -Headers $Headers `
                        -Method Patch `
                        -ContentType 'application/json' `
                        -Body $UpdatedRule | Out-Null
            
                    Write-Host "Successfully updated the $($Rule) rule for $($Zone.name)"
                }
                catch {
                    Write-Host "Error occurred: $_"
                }
            }
        }    
    }
}