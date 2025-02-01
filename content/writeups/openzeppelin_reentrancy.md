+++
author = "Pedro Silva (demon-i386)"
title = "OpenZeppelin - Reentrancy"
date = "2025-02-01"
description = "Writeup - EtherNaut (OpenZeppelin) / Reentrancy."
tags = [
    "reentrancy",
    "openzeppelin",
]
categories = [
    "writeup",
    "openzeppelin",
]
series = ["Writeups"]
+++


Neste writeup, apresentamos a resolução do desafio **“Reentrancy”**, do **CTF Ethernaut** (OpenZeppelin), que explora a exploração de um contrato inteligente vulnerável à falha de mesmo nome.
A vulnerabilidade **Reentrancy** é classificada no **OWASP TOP 10 2025** como **SC05:2025** ([OWASP Smart Contract Top 10](https://owasp.org/www-project-smart-contract-top-10/)) e já foi explorada em diversos ataques notáveis, como:

- **The DAO Hack (2016)**
- **Protocolo bZx (2020)**
- **Lendf.me (2020)**
- **Rari Capital (2022)**

Dentre outros casos, esses ataques resultaram em prejuízos financeiros massivos para as empresas afetadas.


![](../attachment//0b5e7dc7ebea1727718fdb4d07662179.png)


O desafio começa com a seguinte proposta:

![](../attachment//680f5ead4ca7a0f7a135ed3b7d45f52c.png)

```
O objetivo deste nível é que você roube todos os fundos do contrato.

	Coisas que podem ajudar:

- Contratos não confiáveis podem executar código onde você menos espera.
- Métodos de fallback.
- Propagação de throw/revert.
- Às vezes, a melhor maneira de atacar um contrato é usando outro contrato.
- Consulte a página "?" acima, seção "Além do console".
```

Junto ao código do contrato implementado:

![](../attachment//5605e192f80bae1ffe0e9d8a5e85ec17.png)

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;
import "openzeppelin-contracts-06/math/SafeMath.sol";

contract Reentrance {
    using SafeMath for uint256;
    mapping(address => uint256) public balances;

    function donate(address _to) public payable {
        balances[_to] = balances[_to].add(msg.value);
    }

    function balanceOf(address _who) public view returns (uint256 balance) {
        return balances[_who];
    }

    function withdraw(uint256 _amount) public {
        if (balances[msg.sender] >= _amount) {
            (bool result,) = msg.sender.call{value: _amount}("");
            if (result) {
                _amount;
            }
            balances[msg.sender] -= _amount;
        }
    }
    receive() external payable {}

}
```

Analisando o código, é possível identificar 3 (três) funções públicas:
- `donate(address _to)`: É uma função **payable**, ou seja, permite que a função receba **Ether**. Recebe como argumento um endereço `_to` e adiciona ao saldo desse endereço no **mapping** `balances` o valor enviado no campo `msg.value` da transação.
- `balanceOf(address _who)`: Recebe como argumento um endereço através do campo `_who` e retorna seu saldo armazenado no **mapping** `balances`.
- `withdraw(uint256 _amount)`: Permite que um usuário saque uma quantidade `_amount` de **Ether**, desde que tenha saldo suficiente. O saque é realizado chamando `msg.sender.call{value: _amount}("");`, que envia o valor solicitado ao iniciador da transação (`msg.sender`), atualizando seu saldo ao final da transferência, conforme descrito no trecho: `balances[msg.sender] -= _amount;`.


O objetivo do desafio é roubar todo o **Ethereum** armazenado no contrato, representando um total de 0.001 eth.

![](../attachment//ff86fe209d0476bafd088cc40b01ab75.png)

Observando as funções expostas pelo contrato, foram realizadas algumas considerações.
- A função **withdraw** requer que o valor do saque seja menor que o valor armazenado como saldo no endereço do usuário, armazenado no **mapping** `balances`. Trecho de código: (`if (balances[msg.sender] >= _amount) {`)
- A subtração do saldo do usuário é realizada após a chamada ao método `call`.

A vulnerabilidade no contrato surge quando ele realiza uma chamada externa sem antes atualizar seus valores internos, fato que leva a um problema de **race condition** (condição de corrida), onde um atacante consegue interferir na execução do contrato antes que trechos de código importantes sejam executados, no caso, antes que o valor de seu saque seja subtraído na lógica interna do contrato.

O ataque de *reentrancy*, ou reentrada (em brazuca), ocorre através da exploração dessa primitiva, onde um atacante força a execução uma funcionalidade especifica de um contrato externo de modo recorrente.

Para explicar a realização do ataque é necessário ter o entendimento de que existe uma função especial no Solidity chamada `receive`, chamada automaticamente sempre que um contrato recebe **Ether**.


## Passo a passo de chamadas realizadas entre contratos


**Contrato Vulnerável**:  
O contrato vulnerável realiza uma **chamada externa** (`call()`, no caso do contrato analisado) antes de atualizar o seu estado interno. A chamada é realizada para o contrato no controle do atacante.


**Primeira Chamada do Atacante**:  
O atacante, por meio de um contrato malicioso, deposita **Ether** no contrato vulnerável e chama a função de **saque** (`withdraw`). O contrato vulnerável **verifica** se há saldo suficiente e envia o Ether para o atacante.
- Importante: Até então, o saldo interno do contrato não foi atualizado, já que a função `call()` foi chamada em um contrato externo.
- Segundo a documentação, a função `call()` passa o contexto de execução para o contrato alvo: "*Calling a function on a different contract (instance) will perform an EVM function call and thus switch the context such that state variables in the calling contract are inaccessible*." - https://docs.soliditylang.org/en/latest/contracts.html

**Execução da Função `receive()` do Atacante**:  
Quando o contrato vulnerável envia **Ether** ao atacante, **a função `receive()`** do contrato malicioso é chamada automaticamente.  
Dentro dessa função `receive()`, o atacante pode **reentrar** na função de saque (`withdraw`) do contrato vulnerável.
- Ao reentrar na função `withdraw`, sua execução é começa novamente, sendo novamente chamada a função `call()` com o contrato malicioso, ignorando novamente a etapa de subtração do saldo do usuário.


**Reentrada na Função `withdraw`**:  
O atacante, dentro da função `receive()`, chama **novamente** a função `withdraw()` do contrato vulnerável **antes que o saldo interno** do contrato seja atualizado. Como o saldo do atacante ainda não foi subtraído, ele consegue retirar mais **Ether** do contrato vulnerável.

**Execução Recursiva**:  
O processo de reentrância se repete: a cada chamada de `receive()` e reentrada em `withdraw()`, o atacante consegue **sacar mais Ether** do contrato vulnerável, sem que o contrato vulnerável consiga atualizar seu estado interno, visto que o `call()` transfere a execução ao contrato arbitrário.

A execução desse loop ocorre até que o gás acabe ou que todos os fundos do contrato sejam drenados.


![](../attachment//4a18e8d9e57d38519568e8bfa6aca805.png)


## Exploit!


Para exploração da vulnerabilidade de reentrada, encontrada após a análise do contrato, é então criado um contrato malicioso conforme descrito abaixo.


![](../attachment//0178a13de8653455b972f704064127cc.png)

Funções criadas:
- `exploitDonate()`: Realiza uma chamada ao método `donate` do contrato alvo, com uma transferência de um valor em **Ether**, necessário para cumprir o requisito do método `withdraw`.
- `exploitWithdraw()`: Realiza uma chamada ao método `withdraw` do contrato alvo, com uma transferência de um valor em **Ether**, que serve como argumento para indicar o valor que deve ser transferido para o contrato, e que não pode ser maior que o previamente depositado.
- `withdrawAll(address payable _to)`: Realiza o saque de todo o **Ether** armazenado no contrato malicioso para um endereço arbitrário, utilizado para sacar o **Ether** roubado para nossa carteira pessoa.
- `receive()`: Função especial, definimos em sua lógica uma chamada para a função `withdraw` do contrato vulnerável, reentrando na função após a transferência de contexto empregada pela função `call()`.


```
// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.8.2 <0.9.0;


interface IExternalContract {
    function donate(address _to) external payable;
    function balanceOf(address _who) external view returns (uint256 balance);
    function withdraw(uint256 _amount) external;
}

  
contract Exploit {
    IExternalContract private immutable targetContract;
    constructor(address _targetContract) {
        targetContract = IExternalContract(_targetContract);
    }

    function exploitDonate() public payable {
        require(msg.value > 0, "Precisa enviar ETH");
        targetContract.donate{value: msg.value}(address(this));
    }

  

    // Função withdraw que requisita saque de valor especificado
    function exploitWithdraw() public payable {
        targetContract.withdraw(msg.value);
    }

  

    // Função para sacar todo o saldo do contrato
    function withdrawAll(address payable _to) public {
        require(address(this).balance > 0, "Sem saldo para sacar");
        _to.transfer(address(this).balance);
    }

  

    // Recebe ETH e tenta realizar um saque do contrato externo
    receive() external payable {
	        if (address(targetContract).balance >= msg.value) targetContract.withdraw(msg.value);
    }

}
```

A imagem abaixo demonstra o contrato criado já na blockchain.

![](../attachment//026a4e99ece2fc20f5a9c051a1f7a283.png)

#### 1. Função `exploitDonate()`

Enviando transação para depósito de 2 finney para contrato alvo.

![](../attachment//3e3e1e492c88995fb22e8510c487b4e2.png)

Valor total após deposito no contrato alvo:

![](../attachment//319b8b62d377ed1edd3058717c0e0ab8.png)

Registro da transação efetuada pelo contrato malicioso na blockchain após transferência de 0.002 finney.

![](../attachment//052473cfb058735e3025efd15f551dd3.png)


#### 2. Função `exploitWithdraw()` - Final!

É importante lembrar que a execução de chamadas entre contratos consome **gás**. Isso inclui tanto a execução de código dentro de um contrato quanto a transferência de dados entre contratos. Portanto, ao explorar uma falha como a de **reentrância**, onde chamadas recursivas são feitas dentro de um contrato, é importante garantir que haja **gás suficiente** alocado para cobrir a execução dessas chamadas.

Caso o **gás** alocado seja insuficiente para cobrir toda a execução de uma transação, o processo será **revertido**, o que significa que todas as mudanças feitas até aquele ponto serão desfeitas, e o estado do contrato será restaurado ao seu valor anterior. Isso pode impedir que o atacante tenha sucesso no ataque, caso ele não consiga consumir gás suficiente para completar as operações recursivas

O **gás** é uma unidade que mede o custo computacional necessário para executar uma operação na blockchain do **Ethereum**. Cada operação, como transferências ou execução de código de contratos tem um custo associado em termos de gás. Esse custo é determinado pela complexidade da operação e pela quantidade de dados que ela manipula. Ele é como se fosse um imposto empregado pela rede para impedir, por exemplo, execução infinita de funções.

"intenção do sistema de taxas é exigir que um invasor pague proporcionalmente por cada recurso que consome, incluindo computação, largura de banda e armazenamento, portanto, qualquer transação que leve a rede a consumir uma quantidade maior de qualquer um desses recursos deve ter uma taxa de gás mais ou menos proporcional ao aumento."

Executando método `ExploitWithdraw()`, parte final para execução do ataque de *reentrancy*, visto que após essa chamada, todas as subsequentes irão ser executadas diretamente na função `receive()`.


![](../attachment//603a9b68398d83237b8415d9e670cfc4.png)


#### Aftermath

Após a execução do método `exploitWithdraw()`, foi criado um loop dentro de ambos os contratos malicioso e alvo, onde o contrato malicioso, abusando da ausência de atualização de seu saldo pelo contrato real, forçou a execução da função de saque do contrato alvo até o fim de suas reservas de **Ether**.

Sempre que o contrato alvo realizava uma transferência de **Ether** por meio do método `call()`, o **contexto de execução** (e o **Ether** sacado) era transferido para o contrato malicioso. Isso fazia com que o contrato malicioso **reentrasse** na função de saque do contrato alvo **antes que o saldo interno fosse atualizado**, impedindo que o contrato alvo registrasse a subtração do valor sacado.

Essa falha permitiu que o contrato malicioso executasse a função de saque de forma **recursiva** até que o saldo do contrato alvo fosse totalmente drenado. 

![](../attachment//d86a395e3da225108e0334086fe4509d.png)

É possível observar o histórico de transações internas realizadas pelo contrato, com inúmeras transferências realizadas do contrato alvo para o malicioso.
(em vermelho, transações recebidas pelo contrato alvo)

![](../attachment//5ea6814af784252b6f8abeb35692ca99.png)

#### Profit!

Com o contrato malicioso em posse das reservas de **Ether** do contrato alvo, é possível realizar o saque de sua reversa interna para nossa carteira pessoal. 


![](../attachment//e84f8d85710a58eb4467f9aee2ff2def.png)

Estado da Carteira antes da realização do saque:

![](../attachment//cbe18827d7ea464654de6447115abb5a.png)


Estado da Carteira depois da realização do saque:

![](../attachment//4240605e3681136e0fd441ee5c991d40.png)

#### FIN!
