# SimpleCrypto.Standard
Reimplementation of SimpleCrypto.Net as a .Net Standard Library. Provides easy use of the PBKDF2 algorithm.

# Goal of this project
Create a nuget package called `SimpleCrypto.Standard`that is fully compatible to the mentioned SimpleCrypto.Net library.
 The library wraps around the PBKDF2 implementation of C# and provides easy access to generate secure hashs.

# Nuget
You can find this package on [Nuget](https://www.nuget.org/packages/SimpleCrypto.Standard/).
To install the latest version via the Package Manager Console use

`PM> Install-Package SimpleCrypto.Standard`

If you prefer to user the .NET CLI use

`> dotnet add package SimpleCrypto.Standard`

# Requirements

Version `0.2.x` requires Net Standard 2.0. Future versions require Net Standard 2.1

# Usage
You can find a basic example in the `SimpleCrypto.ConsoleSample` Project.

## Standard Configuration
```csharp
IPbkdf2 pbkdf2 = new Pbkdf2();

string password = "MySecretPassword"

// Compute the hash of the password. As no Salt is provided the call will generate the Salt.
string hash = pbkdf2.Compute(password);

//Additional to the hash, you have to save the Salt. You can access it via a Property of the pbkdf2 object.
string salt = pnkdf2.Salt

// Compare two hashs (or strings) in constant Time.

bool areEqual = pbkdf2.Compare(savedHash, computedHash);
```

## Configure Salt-, Hashsize and iterations,

The `Compute` methode provides several overrides to allow different configurations. If the default overrides dont fit your needs,
you cant set the public properties you need.
For example: Compute the Hash with a Saltsize of 18 and an Iterationcount of 200 000 you can use the override:

```csharp
string hash = pbkdf2.Compute("TextTohash", 18, 200000)
```