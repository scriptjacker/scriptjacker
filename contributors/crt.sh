#!/bin/bash

echo "
        "

        Help()
{
   # Display Help
   echo "Options:"
   echo ""
   echo "-h     Help"
   echo "-d     Search Domain Name       | Example: $0 -d hackerone.com"
   echo "-o     Search Organization Name | Example: $0 -o hackerone+inc"
   echo ""
}

        # Request the Search  with Domain Name
        Domain() {
        requestsearch="$(curl -s "https://crt.sh?q=%.$req&output=json")"
                 
                         echo $requestsearch > req.txt
                         cat req.txt | jq ".[].common_name,.[].name_value"| cut -d'"' -f2 | sed 's/\\n/\n/g' | sed 's/\*.//g'| sed -r 's/([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4})//g'
                         rm req.txt
                         echo ""
}                
    # Request the Search with Organization Name
        Organization() {
        requestsearch="$(curl -s "https://crt.sh?q=$req&output=json")"
                 
                         echo $requestsearch > req.txt
                         cat req.txt | jq ".[].common_name"| cut -d'"' -f2 | sed 's/\\n/\n/g' | sed 's/\*.//g'| sed -r 's/([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4})//g'
                         rm req.txt
                         echo ""

}

if [ -z $1 ]
        then
                Help
                exit
        else
                req=$2
                
fi

while getopts "h|d|o|" option; do
   case $option in
      h) # display Help
         Help
         ;;
      d) # Search Domain Name
         Domain
         ;;
      o) # Search Organization Name
         Organization
         ;;
     *) # Invalid option
          Help
          ;;
                 
   esac
done
