# Sublime Rules
by Sublime Security Modified by Greasy Weasel

This repo contains open-source rules for Sublime, a free and open platform for detecting and preventing email attacks like BEC, malware, and credential phishing. The rules in this Repo have been modified to be more compatable with Mimecasts URL re-writing. As Mimecasts URL rewriting is not reversable without using an API, the only option is to use the "Display URL Destination Domain" setting as documented here: https://community.mimecast.com/s/article/email-security-cloud-gateway-configuring-url-protection-definitions

The file /scripts/change-url-to-mimecast.py/replacements.yml controls replacement.

# Structure

- Detection-rules = orignal detection rules
- discovery-rules = original discovery rules
- mimecast-detection-rule = modified rules 

# Sublime Configuration

1. Disable and uninstall all rules in the Sublime Core Feed
2. Create a new feed called some like "Sublime Core Feed - Mimecast"
3. Settings for feed:
   - Git URL: https://github.com/greasy-weasel/sublime-rules-mimecast.git
   - Git branch: main
   - File filter for MQL detection rule files: mimecast-detection-rule/*.yml
   - File filter for YARA signature files: yara/*.yar
   - Other settings are irrelivant 

# Examples

## Simple replacements, example:

    orig:
      .href_url.domain.root_domain != sender.email.domain.root_domain
    replace:
      not(strings.ends_with(.href_url.query_params,sender.email.domain.root_domain))
This will just replace one string with another when found in a body.links block


## The script can also perform wildcard replacements, example:

    orig: |
      .href_url.domain.domain not in $$
    replace: |
      not(any($$, ..href_url.query_params == strings.concat("domain=",.)))

This will look for any line containing a $list e.g.

    .href_url.domain.domain not in $listname
will become:

    not(any($listname, ..href_url.query_params == strings.concat("domain=",.)))


## Another wildcat example:

    orig: |
      .href_url.domain.root_domain in ()
    replace: |
      any([], strings.ends_with(..href_url.query_params,.))

This will replace anything with () in brackets:

    .href_url.domain.root_domain in ("baddomain.com","worsedomain.com")
will become:

    any(["baddomain.com","worsedomain.com"], strings.ends_with(..href_url.query_params,.))


## Another wildcard example:

     orig: |
       .href_url.domain.domain == ""
     replace: |
       .href_url.query_params == "domain=##"

This can be used to replace the " marks:

    .href_url.domain.domain == "baddomain.com"
will become:
    .href_url.query_params == "domain=baddomain.com"


# Tags
We also add tags to the rules to give you a better idea of problem rules:

- Mimecast Changes Complete = Needed changes made to rule should be fully compatable with mimecast
- Mimecast Hard to Fix = rules which contain MQL which does contains data removed by mimecast and noway to achieve equivalent functionality
- Mimecast Needs Fix = Needs to more work to fix
- Link Analysis Present = Link analysis present in rule

