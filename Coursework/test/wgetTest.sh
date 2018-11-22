#! /bin/bash
for ((i=0;i<=$1;i++))
do
	wget www.bbc.co.uk/news
done
rm news*