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

[ad1](images/1.png)

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

[ad2](images/2.png)

>[!NOTE]
>The diagram has had some arrows showing trusts left off because it would be cluttered - essentialy because there is a two-way transitive trust created between the trees in our forest *all* domains in TEZZLA.COM can access *all* domains in TEZZLA.ORG and vice-versa

The idea of having a transitive two way trust relationship established by default when trees are joined in a forest is that authentication and access to resources is easy across *all* the domains and child domains in the forest.
