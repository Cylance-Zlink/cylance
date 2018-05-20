import cylance as cy

# Script to get offline devices and write to file

# CONF
tenant = ""         # Tenant ID
app = ""            # Application ID
secret = ""         # Application Secret

# ***** PART 1 - GENERATE JWT TOKEN ***** #

def main_loop():
    cy.set_creds(tenant, app, secret)
    # Note, get_token() only needs to be called once, the cylance module takes care of expiration and renewal of token automagically
    cy.get_token()

# ***** PART 2 and 3 - GET OFFLINE DEVICES  ***** #
    print cy.get_data("DEVICES", 'state=offline out=devices_after.json')

main_loop()
