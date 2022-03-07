# LogonBox Authenticator API for Java

[![Java CI with Maven](https://github.com/nervepoint/logonbox-authenticator-java/actions/workflows/maven.yml/badge.svg)](https://github.com/nervepoint/logonbox-authenticator-java/actions/workflows/maven.yml) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.nervepoint/logonbox-authenticator-java/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.nervepoint/logonbox-authenticator-java)

Use this API to integrate LogonBox Authenticator into your own Java application authentication flows.  

The LogonBox Authenticator uses an authentication mechanism similar to SSH private key authentication where users keys are published in an authorized keys listing on the credential server. This API will read the trusted public keys and then submit an authentication request payload to the credential server for signing by the corresponding private key. 

As part of the signing operation, the user must authorize the request within the LogonBox Authenticator app. Once authorized the payload is signed by the private key, which is held exclusively within the secure storage of the app. 

To authenticate the user, the API verifies the signature returned to obtain the authentication result.

# About LogonBox Authenticator

Safeguard your people, passwords and apps with [LogonBox's](https://logonbox.com) 2-Factor [Authentication app](https://www.logonbox.com/content/logonbox-authenticator/) for Android and iOS. 

<img src="src/web/logonbox-logo.png" width="256">

## Other Languages

 * [Python](https://github.com/nervepoint/logonbox-authenticator-python)
 * [Node/Javascript](https://github.com/nervepoint/logonbox-authenticator-nodejs)
 * [PHP](https://github.com/nervepoint/logonbox-authenticator-php)

## Installation

### Release

No release yet on Maven Central, coming soon.

### Snapshots

Snapshots are available in the Sonatype Snapshot Repository.

```xml
<dependencies>
	<dependency>
		<groupId>com.nervepoint</groupId>
		<artifactId>logonbox-authenticator-java</artifactId>
		<version>0.0.1-SNAPSHOT</version>
	</dependency>
</dependencies>

...

<repositories>
	<repository>
		<id>snapshots-repo</id>
		<url>https://oss.sonatype.org/content/repositories/snapshots</url>
		<releases><enabled>false</enabled></releases>
		<snapshots><enabled>true</enabled></snapshots>
	</repository>
</repositories>
```

## Usage

There are many ways the authenticator can be used and this will depend on your authentication use case.

### Server Redirect

If you are logging a user into a web application, you can create a request, and redirect the user to a URL on the credential server where they are prompted to authorize the request on their device. This eliminates the need for you to create your own user interface and provides a modern, clean authentication flow. 

When authentication completes, the server redirects back to your web application with an authentication response which you pass into the API for verification. 

#### Generate a Request and Redirect to the Credential Server
```java
/** Create a client and configure it with the LogonBox server **/
AuthenticatorClient client = new AuthenticatorClient("tenant.logonbox.directory");

/** Generate a request passing a URL for the redirect back to your webapp.
Note how {response} is used to place the servers response into the redirected URL **/
AuthenticatorRequest request = client.generateRequest(username,
    "https://localhost/app/ui/authenticator-finish?response={response}");

/** Save the request so it can be picked up when we receive the response **/
req.getSession().setAttribute(AUTHENTICATOR_REQUEST, request);

/** Now redirect the user to the URL provided by the AuthenticationRequest **/
response.sendRedirect(request.getUrl());
```

#### Process the response
```java
/** Grab the authenticator request out of the HTTP session **/
AuthenticatorRequest request = (AuthenticatorRequest) 
    req.getSession().getAttribute(AUTHENTICATOR_REQUEST);

/** Get the servers response from the URL parameters **/
String response = req.getParameter("response");

/** Pass the response into the authenticator request to get the response. **/
AuthenticatorResponse resp = request.processResponse(response);
			
/** Verify the response **/
if(resp.verify()) {
    // The user has authenticated.
}
```


### Direct Signing

If you are using a different protocol and cannot redirect the user via a web browser, or want to provide your own user interface, you can perform authentication exclusively through the API. 

```java
/** Create a client and configure it with the LogonBox server **/
AuthenticatorClient client = new AuthenticatorClient("tenant.logonbox.directory");

/** Send the request, and receive the signed response. 
The user will receive an authentication prompt on this call. **/
AuthenticatorResponse resp = client.authenticate("lee@logonbox.com");
	
/** Call verify on the response to validate the authentication. 
Only allowing access to your application when a true value has been returned. **/
boolean success = resp.verify();
```

## Dependencies

There is only one required dependency on Jackson Databind. We would have preferred not to use this, there are of course other JSON parsers around but Jackson generally has the most coverage, for example being included with Spring Boot. The usage is minimal and therefore is likely you can change the version of Jackson used easily to match your own use.

For Java runtimes below version 15 we recommend using [str4d/ed25519](https://github.com/str4d/ed25519-java) project to support ed25519 keys which are our preferred key algorithm (the app will fallback to using a strong RSA key automatically if your runtime does not support ed25519). You will need the following Maven dependency.

```xml
<dependency>
  <groupId>net.i2p.crypto</groupId>
  <artifactId>eddsa</artifactId>
  <version>0.3.0</version>
</dependency>
```

And you should install their JCE provider before using this API.

```java
Security.addProvider(new EdDSASecurityProvider());
```

## Debugging

A simple Logger interface is used that will output to `System.out` and `System.err` by default. You can enable this after you have created the client object.

```java
client.enableDebug();
```

This should be sufficient for testing. To integrate logging into your wider application just provide an instance of `com.logonbox.authenticator.Logger` to the `enableDebug` method.

```java
client.enableDebug(new MyApplicationLogger());
```
