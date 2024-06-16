# Active Directory Introduction

Getting to know Active Directory is essential as it is used in organizations of all sizes and we will therefore be working with it.

AD is also often misconfigured and even low level users can enumerate an AD environment in the hunt for these misconfigurations which can ultimately lead to a complete pwning of a domain.

## High Level Overview

We will take a very high-level look at *domains* and *AD*

### Domains in Windows

Before we start digging into AD it makes sense to briefly consider what a *domain* is.

A domain in windows is a group of users and computers which are under the administration of a specific organisation.

Domains allow businesses to scale up and connect their machines and users on a larger scale.

The main idea of a domain is to centralise the administration of the various parts of a windows network.

With a domain, businesses can centralise identity management so all the users across the domain can be configured using Active Directory. Security policies can also be configured using Active Directoy and then pushed to users and computers across the domain as necessary. 

### High Level Overview of AD

The Active Directory Domain Service is the core of any domain in windows. It acts as a catalogue of all the objects in a domain. These objects come in many forms - they could be users, computers, printers, shared resources, policies and many other things.

AD essentialy lets us manage user *authentication* and *authorization* along with *resources* from a central point.

### Why Use Domains and AD?

The simple answer to this is because by doing so we make it much easier to manage resources such as computers, users, file shares, policies etc

If we imagine that we have a small business which has ten computers and about the same number of employees all working in one office it seems feasible that we could manage everything quite easily. We could set local users up on their machines and we could update the machines individually, too. It would be straightforward to tweak policies on the machines and install software machine by machine.

In such an situation we might choose not to use a domain and AD - but what if we need to manage a medium sized business which has several hundred computers and more than that employees based in several different offices?

Clearly, going around each machine in the different offices every time we want to run an update or change a policy is insane.

Now imagine a larger business which has thousands of machines and thousands of employees based in more than one country.

The need to use domains and therefore AD to manage them becomes clear when we consider such scenarios.

## Active Directory Fundamentals

In this section we will look at the basics of AD

### Active Directory Structure

AD is a service for network environments which use windows machines.

Its great strength is that it lets us manage resources along with authentication and authorization from a central point - this is essential when working with larger networks.

This leads to a very important point - AD is easily and often *misconfigured* - this is especially true when it is being used to manage large environments.

We mentioned earlier that a simple user on an AD environment can enumerate lots about the domain without needing extra privileges to do so. Some of the data which such a user can enumerate is:

- [x] Domain Users
- [x] Domain Computers
- [x] Domain Groups
- [x] Organizational Units
- [x] Domain Policies - Password Policies For Example
- [x] Group Policy Objects
- [x] Access Control Lists
- [x] Much More

With this in mind - let us start looking at the *structure* found in AD

The first point to note is that AD is *hierarchical* - it uses a *tree structure*

#### Domains

We will start with *domains*.

Domains are collections of objects which are logically grouped together. They provide a boundary when it comes to applying policies to objects and groups of objects.

It is within the domains that we find objects such as computers, users and groups.

Each domain has its own unique namespace.

To make this more clear we will use an example.

In our example we can imagine that we have created a company called TEZZLA - we started it in America and we created a domain for it called TEZZLA.COM

Over time our business grows and we start operating in Australia and China. We therefore create a domain for our Chinese operations and a different domain for our Australian operations.

This makes sense as there are differences with time-zones and languages - Australian is very hard to understand - so by creating domains we can let the domain admins in those countries manage things.

These new domains are *children* of the *parent* domain TEZZLA.COM

>[!NOTE]
>All the child domains in a tree share a namespace with the parent domain - this is an easy way to see that the domains are in a tree together

#### Trees

We are essentialy creating a *tree* which is the next container up in the AD structure. A *tree* is a collection of domains which have a parent - child relationship as in our example.

In our example we will create AU.TEZZLA.COM and CN.TEZZLA.COM

![ad1](images/1.png)

The lines in the diagram represent *trust relationships*

The default trust relationship in AD when a child domain is created is *two-way transitive* trust.

This means that the parent domain trusts the child domain and the child domain trusts the parent domain. This means that the users in TEZZLA.COM can access CN.TEZZLA.COM and users in CN.TEZZLA.COM can access TEZZLA.COM

Furthermore - because the trust relationship is *transitive* the *sibling domains* of CN.TEZZLA.COM and AU.TEZZLA.COM have a two-way trust as well.

>[!IMPORTANT]
>Just because users from AU.TEZZLA.COM can access CN.TEZZLA.COM domain this does not mean they can access every resource - the level of access to resources is still determined by permissions granted to the user accounts or the groups they belong to

#### Forests

Next we come to the top level container of an AD environment - the *forest*.

Forests are collections of domain trees.

>[!NOTE]
>Technically a forest and a tree are created when we create a domain - a very small forest and tree but a forest and tree nevertheless - mostly though we think of trees as being more than one domain and forests as more than one tree

Forests share a common schema, share a common configuration partition, share a common global catalogue to enable searches, enable trusts between all domains in the forest and share enterprise admins and schema admins.

>[!IMPORTANT]
>Enterprise admins are the *highest privileged* users in an AD forest - domain admins, schema admins and administrators are also privileged users but *enterprise admins* have a *forest wide* scope

The trees in a forest can have different namespaces - working with our example this could be a tree which uses TEZZLA.ORG as its root domain.

>[!NOTE]
>Each tree has a *root* domain - this is the first domain which is created in the namespace of the tree - the first domain in the first tree also serves as the *forest root* domain and has special significance

Hopefully the diagram below will start to make things more clear.

![ad2](images/2.png)

>[!NOTE]
>The diagram has had some arrows showing trusts left off because it would be cluttered - essentialy because there is a two-way transitive trust created between the trees in our forest *all* domains in TEZZLA.COM can access *all* domains in TEZZLA.ORG and vice-versa

The idea of having a transitive two way trust relationship established by default when trees are joined in a forest is that authentication and access to resources is easy across *all* the domains and child domains in the forest.

## Active Directory Objects

We find *classes* in the AD schema - the schema serves as a blueprint for AD

We can instantiate objects from these classes - this is similar to how we can instantiate objects from classes in Object Oriented Programing based languages such as python.

These objects are used by AD to represent network resources such as users and computers. They have *attributes* but not *methods*

The attributes vary according to the class the object has been instantiated from - a user object for example can have attributes such as *name* | *email* | *password* etc

In short - *any* resource we find in AD is actually an *object*

### User Objects

Since we are learning about AD and domains - the users we are refering to in this section are *domain users* which are different to *local user accounts*

Domain users are managed from a *domain controller* - a server which is essentialy the main brains in an AD environment.

Domain users can access resources across the entire domain - they can for example log into any machine which is joined to the domain.

When we refer to *user objects* in this section we are therefore referencing domain users.

User objects are very common in AD - they are also frequently targeted as pwning a user allows attackers to further enumerate AD and extend their attack.

In most organizations there will be *at least* one user account for each employee - some employees have more than one account for example IT staff who have an admin and standard account.

We will also find lots of *service accounts* and old accounts which are no longer activated - this means we will find many user accounts when we are working with organizations using AD

>[!IMPORTANT]
>Users are a weak link in any domain - they might use terrible passwords | share passwords | install dodgy apps | click on phishy links | other silly acts

User objects are one of the objects which are known as *security principals*.

Security principal objects such as users can be authenticated by the domain and given privileges over resources like files and printers in the domain.

We can see security principal objects as being able to act on resources in the network.

Since user objects are security principals they have a Security IDentifier and a Global Unique IDentifier.

User objects can have hundreds of attributes - but some are more common than others - common attributes include:

- Display Name
- Last Login Time
- Address
- Hundreds More

>[!NOTE]
>The UserPrincipalName attribute is the main logon name for a user account and conventionaly it will be the email address of the user

Some other important *attributes* of *user* objects are given below.

- ObjectGUID | this is a unique identifier and never changes
- SAMAccountName | a logon name which is used in authentication and authorization processes - it supports previous versions of Windows clients and servers
- objectSID | this is the Security IDentifier and is used in various interactions related to security
- sIDHistory | contains previous versions of SIDs - often found when user objects have migrated from domain to domain - once they have migrated they will have a new SID which becomes the objectSID whilst their previous SID goes to sIDHistory

Users can be people such as employees who need to access the network, but they can also be services such as IIS or MSSQL.

Every service needs a user to run, but *service users* are restricted to having only the privileges which they need in order to run their service.

Each user has a unique account which uses a username and a password to log into computers in domains and to then access network resources.

>[!NOTE]
>User objects are *leaf* objects which means they cannot contain other objects - they can be placed into other objects however such as *groups* and *organizational units*

![ad3](images/3.png)

![ad4](images/4.png)

![ad5](images/5.png)

![ad6](images/6.png)

#### Local Accounts

Even though we are looking at AD and domain users - it makes sense to get to know a little more about *local user* accounts.

These accounts are created on standalone machines and they can therefore not access resources across a domain.

The authentication for these accounts is handled by the local machine via the *Local Security Authority Subsystem Service*

LSASS takes the credentials entered by a user and hashes the plaintext password. It then interacts with the *Security Account Manager* database which is stored on the local machine at `\Windows\System32\Config\SAM` LSASS retrieves the stored password hash for the user and compares the input password hash with it - if they match the user is authenticated to the *local* machine.

LSASS will generate a *security token* for the authenticated user - this essentialy determines what they can do on the system via their SID | group memberships and privilege data.

Once the token has been created, it is attached to the users session.

>[!IMPORTANT]
>All of the authentication occurs on the *local* machine - no *domain controllers* are involved so *local user* accounts *cannot* access resources across a domain

##### Default Local User Accounts

We can create local user accounts but there are some default ones which are created automatically.

- Administrator | this account has full control over most of the *local* system and is the first account created - it has an SID of `S-1-5-21-<MACHINE-IDENTIFIER>-500`
- Guest | disabled by default and usually left disabled as it has a blank password and allowing anonymous access to a machine is not a great idea
- SYSTEM | this is the NT AUTHORITY\SYSTEM account - it is used by the operating system and many of its crucial services - it is the *most* privileged local account having more privileges than even an administrative user account - it is a *service* account and its SID is `S-1-5-18`
- Local Service | this account is used by services which only need low privileges
- Network Service | this account is similar to the *Local Service* account in that it has low privileges on the *local* system - it is used by services which need to interact with network resources

>[!TIP]
>The last part of an SID is called the *Relative IDentifier* - it makes each full SID unique - if we see it is `500` we know we are looking at the default *Administrator* account | standard local user accounts typically begin at `1001` and increment from there as they are created

![ad7](images/19.png)

### Computer Objects

Computer objects in AD are used for devices which join the domain. These machines can be clients or servers. In addition, these devices can either be physical or virtual machines.

Computer accounts are considered *security principals* as they can act on other resources in the domain. They have their own unique name and Global Unique IDentifier as well as a Security IDentifier.

Computer objects are *leaf* objects so they cannot contain other AD objects.

Since a secure trust relationship is established between a machine and a domain, computer objects can authenticate to other objects in the domain - such as other machines - and they can access network resources.

Computer objects can authorize users from the domain.

Each computer account has its own *security context* to operate across the domain - they do not have NT AUTHORITY\SYSTEM status on other machines within the domain.

The security context of the computer accounts can be altered by domain admins - for example they could allow a machine to access shared folders or printers.

>[!IMPORTANT]
>Even though computer accounts do not operate with elevated privileges on other machines in a domain - they are still *high value targets* because if we pwn one we will still have *read* access to lots of the domain and therefore will be able to *enumerate* AD to further our attacks

Having a machine joined to a domain rather than not being joined - a host not joined to a domain will be part of a *workgroup* - gives benefits.

When a machine is joined to a domain it can easily share and access resources. Policies can more easily and consistently applied via the domains *group policy*

If a machine is only part of a *workgroup* and not joined to a domain it is more difficult to share resources with other machines and changes to policies need to be performed on each machine locally.

>[!TIP]
>If we gain access to a domain via a computer account it is well worth our while to use it to enumerate the domain as well as loot locally stored data such as passwords, ssh keys and sensitive files - remember - a computer account in AD has pretty much the same rights as a domain user so it will have read access to lots of the domains data

![ad7b](images/7.png)

![ad13](images/13.png)

![ad14](images/14.png)
