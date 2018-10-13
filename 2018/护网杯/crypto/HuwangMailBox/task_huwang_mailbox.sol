pragma solidity ^0.4.24;

contract HuWangMailBox {
    Mail[] drafts;
    address public owner;
    mapping(address => Mail[]) mails;
    
    constructor() public payable {
        owner = msg.sender;
    }

    struct Mail {
        bytes32 text;
        address sender;
    }

    function sendMail(address target, bytes32 text) public {
        mails[target].push(Mail({text: text, sender: msg.sender}));
    }

    function readMail(uint index) public view returns(address, bytes32) {
        require(index < mails[msg.sender].length, "Wrong index");
        return (mails[msg.sender][index].sender, mails[msg.sender][index].text);
    }

    function modifyMail(address target, uint index, bytes32 text) public {
        require(index < mails[target].length, "Wrong index");
        require(msg.sender == mails[target][index].sender, "You are not the sender!");
        mails[target][index].text = text;
    }

    function mailCount() public view returns(uint) {
        return mails[msg.sender].length;
    }

    function dropLastMail() public {
        require(mails[msg.sender].length > 0, "No more mails");
        mails[msg.sender].length--;
    }

    function saveDraft(bytes32 text) public {
        Mail mail;
        mail.text = text;
        drafts.push(mail);
    }

    function readDraft(uint index) public view returns(bytes32) {
        require(index < drafts.length, "Wrong index");
        return drafts[index].text;
    }

    function draftCount() public view returns(uint) {
        return drafts.length;
    }

    function modifyDraft(uint index, bytes32 text) public {
        require(index < drafts.length, "Wrong index");
        drafts[index].text = text;
    }
}
