# Call Stack Spoofing



## Introduction



### What is a call stack?

When a thread running function "A" calls function "B", the CPU automatically saves the current instruction address to the **`Stack`**. This is known as the **`return address`**. Return addresses can be retrieved through a process called [stack walking](https://learn.microsoft.com/en-us/windows/win32/debug/capturestackbacktrace).





## References

{% embed url="https://www.elastic.co/security-labs/peeling-back-the-curtain-with-call-stacks?ultron=esl:_threat_research%2Besl_blog_post&blade=twitter&hulk=social&linkId=234949506" %}

{% embed url="https://klezvirus.github.io/RedTeaming/AV_Evasion/StackSpoofing/" %}

{% embed url="https://labs.withsecure.com/publications/spoofing-call-stacks-to-confuse-edrs" %}

{% embed url="https://posts.specterops.io/abusing-slack-for-offensive-operations-part-2-19fef38cc967" %}

{% embed url="https://www.youtube.com/watch?v=dl-AuN2xsbg" %}
Great talk by this legend
{% endembed %}
