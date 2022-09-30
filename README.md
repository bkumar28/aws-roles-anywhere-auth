# Roles Anywhere Auth to get temporary credentials without using aws signing helper

#### Install dependencies
 ```
  $ pip3 install -r requirements.txt
 ```
 
#### Generate Self Signed Certificate(X509), Private Key, Client CA, Client Chain and Client Private Key
Run shell script [generate_certificates.sh](https://github.com/bkumar28/aws-roles-anywhere-auth/blob/main/generate_certificates.sh) or python script [self_signed_x509.py](https://github.com/bkumar28/aws-roles-anywhere-auth/blob/main/self_signed_x509.py) to generate all certificates
   - Shell Script
      ```
      $ bash generate_certificates.sh
      ```
   **OR**
   - Python Script
      ```
      $ python3 self_signed_x509.py
      ```
####  Create a Roles Anywhere role
We create an IAM role that trusts the IAM Roles Anywhere service and provides clients with permissions to AWS services in our account. This allows IAM Roles Anywhere to assume the role and provide temporary AWS credentials.

   - **Steps are** : 
      - Go to IAM, **Roles**, and click on the **Create Role** button
      - Select **Custom Trust Policy** and paste the following policy as the **Custom trust policy**:
           ```
              {
                  "Version": "2012-10-17",
                  "Statement": [
                      {
                          "Effect": "Allow",
                          "Principal": {
                              "Service": "rolesanywhere.amazonaws.com"
                          },
                          "Action": [
                              "sts:AssumeRole",
                              "sts:TagSession",
                              "sts:SetSourceIdentity"
                          ]
                      }
                  ]
              }
           ```
      - Click **Next**, search for the managed policy **AmazonS3FullAccess**, and select it. 
      - Click **Next** (we will narrow down these permissions later). 
      - Name your role and click **Create Role**

#### Create a Profile to Manage Client Roles and Permissions
A profile in which we specify which IAM roles in our account we want to allow clients to assume via temporary credentials.  
   - **Steps are**:
      - Open the AWS IAM console, go to **Roles**, and at the bottom, under the **Roles Anywhere** section, click **Manage**
      - Click **Create a profile** and provide a name for our profile.
      - Under **Roles**, select your newly created role. You can also add multiple roles here.
      - Under **Session policies, Managed policies**, select the **AmazonS3ReadOnlyAccess** policy. As an example of how we can narrow down the permissions, we will only allow read access to a specific s3 bucket. 
      - For now, we will not use the **Inline policy**, so click **Create a profile**.

#### Create a trust anchor
The trust anchor represents your CA — either an AWS ACM certificate authority or your own. Your clients will authenticate using a client certificate signed by this CA. 

   - **Steps are**: 
      - Open the AWS IAM console, go to **Roles**, and at the bottom, under the **Roles Anywhere** section, click **Manage**
      - Click **Create a trust anchor** and fill in the anchor name. 
      - In our example, we will use our own CA, so select the **External certificate bundle**
      - Under **External certificate bundle** copy your **root-cert.pem** CA certificate file data. 
      - Click **Create trust anchor**
      
####  Update [role_arn](https://github.com/bkumar28/aws-roles-anywhere-auth#create-a-roles-anywhere-role), [profile_arn](https://github.com/bkumar28/aws-roles-anywhere-auth#create-a-profile-to-manage-client-roles-and-permissions), and [trust_anchor_arn](https://github.com/bkumar28/aws-roles-anywhere-auth#create-a-trust-anchor) in [roles_anywhere_auth.py](https://github.com/bkumar28/aws-roles-anywhere-auth/blob/main/roles_anywhere_auth.py) 

####   Update client certificate & Private Key data in roles_anywhere_auth.py
   - [cert_pem_data](https://github.com/bkumar28/aws-roles-anywhere-auth/blob/main/roles_anywhere_auth.py#L42) - Update **client-cert.pem** file data (this is a client certificate pem file)
   - [private_key_data](https://github.com/bkumar28/aws-roles-anywhere-auth/blob/main/roles_anywhere_auth.py#L49) - Update **client-key.pem** file data (this is a client private key pem file)

#### Run python script to get roles anywhere temporary credentials
 ```
  $ python3 roles_anywhere_auth.py
 ```
   
 #### Reference
   - https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication.html
   - https://aws.amazon.com/blogs/security/extend-aws-iam-roles-to-workloads-outside-of-aws-with-iam-roles-anywhere/
   - https://github.com/aws/rolesanywhere-credential-helper
