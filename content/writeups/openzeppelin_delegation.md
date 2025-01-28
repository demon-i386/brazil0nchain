+++
author = "Pedro Silva"
title = "OpenZeppelin - Delegation"
date = "2024-01-27"
description = "Writeup - EtherNaut (OpenZeppelin) / Delegation."
tags = [
    "delegatecall",
    "openzeppelin",
]
categories = [
    "writeup",
    "openzeppelin",
]
series = ["Writeuos"]
+++

Writeup para resolução do desafio "delegation", do CTF Ethernaut, do OpenZeppelin.
Neste writeup, apresentamos uma função bastante interessante utilizada na construção de smart contracts. Além de entender seu funcionamento, também exploramos um caso de vulnerabilidade que pode ser explorado.

![](images/c443f8b24547f0eac7c7ea65b2bb79ae.png)

Desafio começa com a seguinte proposta:

![](images/d73f9657c81f499aaaa980e61b820dc6.png)

´´´
O objetivo deste nível é que você reivindique a propriedade da instância do contrato que lhe foi fornecida.

  Coisas que podem ajudar

- Consulte a documentação do Solidity sobre a função de baixo nível "delegatecall", como ela funciona, como pode ser usada para delegar operações para bibliotecas on-chain e quais implicações ela tem no escopo de execução.
- Métodos fallback
- IDs de método
´´´

Junto ao código do desafio:

![](images/fc51c17a343f36157b73b4bfdcbad055.png)

Logo de cara, analisando o código, é possível identificar dois contratos: um chamado 'Delegation' e outro 'Delegate'.

É importante mencionar que, apesar de parecer que os contratos foram escritos dentro de um único arquivo, eles são completamente independentes, com dois contratos distintos sendo implantados na blockchain. Caso o contrato estivesse utilizando a palavra-chave 'is', ou seja, 'Contract Delegation is Delegate', estaríamos falando sobre herança, com a criação de um único contrato na blockchain, combinando a lógica de ambos, onde um estende as funcionalidades do outro. ([https://docs.soliditylang.org/en/develop/contracts.html#inheritance](https://docs.soliditylang.org/en/develop/contracts.html#inheritance)"

Endereço do dono do contrato e endereço do jogador:

![](images/6e0efefec4bc89751f87c4a220e0b6ea.png)
- Nosso objetivo é fazer o jogador virar o novo dono do contrato.


Analisando o contrato, é possível destacar alguns pontos de interesse, como por exemplo uma função nunca antes vista, chamada "delegatecall":

![](images/04b195151116d471013d897b4420c774.png)

A função **"delegatecall"** faz parte de um conjunto de chamadas utilizadas para interações entre contratos, como **"call"** e **"callcode"**, mas com algumas diferenças entre elas:

**Linha tirada da documentação**: _As mentioned in the introduction, if a library’s code is executed using a CALL instead of a DELEGATECALL or CALLCODE, it will revert unless a view or pure function is called._

{  li e fiquei curioso (????)
- função view: função que pode ler, mas não alterar variáveis definidas em um contrato;
- função pure: função que não poder ler nem modificar o estado da blockchain;
- revert: reverte todas as mudanças realizadas na blockchain.
}

**Call**: O contrato A executa uma função no contrato B em um novo contexto, ou seja, o contrato B pode alterar suas próprias variáveis (estado/armazenamento), mas essas modificações não são refletidas no contrato A. (Modificações no contrato B não afetam o contrato A).

**Delegatecall / Callcode**: O contrato A delega a execução de uma função ao contrato B, permitindo que o contrato B modifique o armazenamento do contrato A. (Modificações no contrato B são refletidas no armazenamento do contrato A).

Fica claro que a execução começa no contrato **"Delegation"**, e isso se torna ainda mais evidente quando enumeramos as funções que o contrato possui (não possui a função **pwn()**):

![](images/7d14f5e796e3d95850b8aa29b1917bbc.png)

Investigando o segundo contrato, podemos observar uma função que é capaz de alterar a variável **owner**, que define o dono do contrato, para o valor recebido através da variável global **msg.sender**. A variável **msg.sender** representa o endereço da conta ou contrato externo que enviou ou executou a transação.


### Exploit

(!!!!) - **Plano**: Através do contrato **Delegation**, vamos utilizar a função **delegatecall** para chamar a função **pwn()** do contrato **Delegate**. Isso fará com que a variável **owner** seja alterada para o endereço de quem originou a transação (no nosso caso, **nós**), assumindo assim a propriedade do contrato.


![](images/485f1acf182ea499aeed5b4cfe59d76c.png)

Mas como interagir com o contrato Delegation para chegarmos ao trecho de código vulnerável? como passamos os argumentos para o "delegatecall"?

Observando o contrato Delegation é observado que o trecho de código está dentro de uma função chamada "fallback()".

Segundo a documentação: *The receive function is executed on a call to the contract with empty calldata. This is the function that is executed on plain Ether transfers (e.g. via `.send()` or `.transfer()`). If no such function exists, but a payable [fallback function](https://docs.soliditylang.org/en/latest/contracts.html#fallback-function) exists, the fallback function will be called on a plain Ether transfer. If neither a receive Ether nor a payable fallback function is present, the contract cannot receive Ether through a transaction that does not represent a payable function call and throws an exception.*

*The fallback function is executed on a call to the contract if none of the other functions match the given function signature, or if no data was supplied at all and there is no [receive Ether function](https://docs.soliditylang.org/en/latest/contracts.html#receive-ether-function). The fallback function always receives data, but in order to also receive Ether it must be marked `payable`.*

A função **fallback** é uma função especial executada no contrato quando nenhuma outra função é encontrada para execução (através do seletor da - 4 bytes de **msg.data**). A forma padrão de invocar a função fallback é através de uma transação.

Podemos passar o argumento global **msg.data**, utilizado pelo **delegatecall**, através do argumento **calldata**, é a área de armazenamento onde os dados da transação (ex: parâmetros) são mantidos.

A função delegatecall leva como argumento a assinatura do método a ser executado dentro do contrato pré-definido. ( address(delegate).delegatecall(metodo_dentro_do_delegate) ).

A assinatura da função é composta pelos primeiros 4 bytes do keccak256 (ou sha3) do seu nome e parâmetros, exemplo:


```
# sha3 completo
var funcSig = web3.utils.sha3('pwn()')
'0xdd365b8b15d5d78ec041b851b68c8b985bee78bee0b87c4acf261024d8beabab'

# 4 bytes
var functionSignature = web3.eth.abi.encodeFunctionSignature("pwn()")
'0xdd365b8b'
```

Para chamar a função **fallback** por meio da biblioteca **web3.js**, utilizada pelo OpenZeppelin, podemos utilizar a função **sendTransaction**, mas funções nativas do Solidity como **call()**, **send()** ou **transfer()** também funcionam.

```
contract.sendTransaction({data:functionSignature,from:player})
```


![](images/d42cbbc3066bc58332acbd18a7e36085.png)

Enviando a transação com o payload:
![](images/cc53f9148290272c34c1a71dc1fca898.png)

Boom! somos os novos donos do contrato!

![](images/37dc865d1e62a4a659507c7e5c00c6e7.png)


