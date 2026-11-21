
static int foo(struct sk_buff *skb)
{
	struct iphdr *iph;

	iph = (struct iphdr *)skb->data;
	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		return -1;
	if (iph->ihl < 5)
		return -1;
	return 0;
}
