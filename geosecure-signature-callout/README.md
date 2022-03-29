# RSA Crypto callout

This directory contains the Java source code for a Java callout for Apigee that
performs RSA signing of data or message payloads

## Example: Verifying

  ```xml
  <JavaCallout name="Java-RsaSign">
    <Properties>
      <Property name='payload'>{payload text}</Property>
      <Property name='private-key'>{private_key}</Property>
    </Properties>
    <ClassName>be.i8c.apigee.geosecure.GeosecureSignature</ClassName>
    <ResourceURL>java://geosecure-signature-callout-{version}.jar</ResourceURL>
  </JavaCallout>
  ```

The result will be written to property 'signature'