# Sniffer-c-
Este fork tem como objetivo a adição do protocolo IGMP a lista de protocolos reconhecidos pelo programa.
Para fazer isso foi necessário a criação do cabeçalho IGMP, o qual concede as informações de checksum, do tipo do IGMP, do MaxResponseTime e do GroupAddress. Além disso, foi adicionada uma tratativa a mais na função listPackets_ItemSelectionChanged (presente no arquivo PraisedSnifferForm.cs) para quando ele receber um pacote IGMP criar o Header apropriado e executar a função MakeInformationIGMP que insere as informações do pacote a árvore mostrada.
Por fim, para conseguir visualizar qualquer protocolo de forma mais fácil, foi adicionado um filtro por tipo de protocolo.

Informações listadas: 
Checksum
Tipo do IGMP
MaxResponseTime
GroupAddress
Origem
Destino
