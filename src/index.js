document.addEventListener('DOMContentLoaded', function(){
    let virustotalKey = "vtkey" in localStorage?localStorage.getItem("vtkey"):"";
    document.getElementById("vtkey").value = virustotalKey;

    async function showHash(hname,hmd5,hasha1,hasha256){    
        document.querySelector('#render').innerHTML += 
        `
        <tr>
            <td><textarea onclick="hcopy(this)">${hname}</textarea></td>
            <td><textarea onclick="hcopy(this)">${hmd5}</textarea></td>
            <td><textarea onclick="hcopy(this)">${hasha1}</textarea></td>
            <td><textarea onclick="hcopy(this)">${hasha256}</textarea></td>
        </tr>
        `;
    }

    async function getSHA256(hash){
        const apikey = document.getElementById('vtkey').value;

        document.querySelector('#ihash').disabled = "true";
        document.body.style.cursor='wait';
        
        const options = {
            method: 'GET',
            headers: {
            Accept: 'application/json',
            'x-apikey': apikey
            }
        };
        try{
            let response = await fetch(`https://www.virustotal.com/api/v3/search?query=${hash}`, options)
            .then(response => response.json())
            .then(response => showHash(response.data[0].attributes.meaningful_name, response.data[0].attributes.md5,response.data[0].attributes.sha1, response.data[0].attributes.sha256))
            
        } catch(err){
            showHash("Not Found: "+hash+"</span>","no data❗","no data❗", "no data❗");
        }

        document.body.style.cursor='default';
        document.querySelector('#ihash').removeAttribute("disabled");
    }
    

    function readCSV(csv){

        let options = {separator:";"}
        let data = $.csv.toArrays(csv,options);
        data.shift();
        
        let interval = 5000; 
        data.forEach((hash,index)=>{
            setTimeout(()=>{
                getSHA256(hash);
            }, index * interval)
        })
    }

    document.querySelector("#submit").addEventListener('click', function(e){
        let hashtxt = document.getElementById('ihash').value;
        getSHA256(hashtxt);
    })

    document.querySelector('#loadcsv').addEventListener('change',function(e){

        let getFile = new FileReader();
        let file = document.querySelector('#loadcsv').files[0];

        getFile.onload= function(){
            readCSV(getFile.result)
        }
        getFile.readAsText(file);
    })

    document.querySelector("#save").addEventListener('click', function(){
        console.log("Saved");
        localStorage.setItem('vtkey', document.getElementById('vtkey').value);
    })

})