<p align="center">
    <img src="https://nodei.co/npm/magic-pump.png?downloads=true&downloadRank=true&stars=true"/>
</p>

<p align="center">
<img src="https://badgen.net/npm/v/magic-pump"/>
<img src="https://badgen.net/npm/dt/magic-pump"/>
<img src="https://badgen.net/npm/license/magic-pump"/>
<img src="https://badgen.net/npm/types/magic-pump"/>
<img src="https://badgen.net/badge/author/MurylloEx/red?icon=label"/>
</p>

# Magic Pump

This useful tool is for you who want to read the same stream multiple times and works exactly like the classic pump.

## What problem does it solve?

The classic pump library cant reuse the same stream to read, what sometimes is needed like in cases that we need pump two or more times a stream like the req (request of Express) for example.

## Usage of Magic Pump

You just have to pass the stream source and stream dest to be pumped and then process your logic in callback.

```javascript
var magicpump = require('magicpump');
var fs = require('fs');

var source = fs.createReadStream('/dev/random');
var dest = fs.createWriteStream('/dev/null');

magicpump(source, dest, function(err){
  console.log('pipe finished', err);
});

setTimeout(function() {
  dest.destroy() // when dest is closed magic pump will destroy source
}, 1000)
```

## Usage of classic Pump

Simply pass the streams you want to pipe together to pump and add an optional callback:

```javascript
var pump = require('pump')
var fs = require('fs')
 
var source = fs.createReadStream('/dev/random')
var dest = fs.createWriteStream('/dev/null')
 
pump(source, dest, function(err) {
  console.log('pipe finished', err)
})
 
setTimeout(function() {
  dest.destroy() // when dest is closed pump will destroy source
}, 1000)
```


## Difference between Magic-Pump and Pump

Let's have a look on the following source code:

```javascript
var source = fs.createReadStream('/dev/random');

function pumpA(data) {
  console.log('the data of pump A is... ', data.toString('utf8'));
}

function pumpB(data) {
  console.log('the data of pump B is... ', data.toString('utf8'));
}

function pumpC(data) {
  console.log('the data of pump C is... ', data.toString('utf8'));
}

pump(source, concat(pumpA), (err) => {
  pump(source, concat(pumpB), (err) => {
    pump(source, concat(pumpC), (err) => {
      console.log('all pipes finished', err);
    });
  });
});
```

If you try execute that, should get an error like this:

```
the data of pump A is...  [content of source stream here]
pipe finished Error: premature close
the data of pump B is... undefined
pipe finished
the data of pump C is... undefined
pipe finished
```

With Magic Pump you can solve this problem! Magic Pump create a new stream in memory and duplicate the buffer if you want read the same stream more than one time. Let's see:

```javascript
var source = fs.createReadStream('/dev/random');

function pumpA(data) {
  console.log('the data of pump A is... ', data.toString('utf8'));
}

function pumpB(data) {
  console.log('the data of pump B is... ', data.toString('utf8'));
}

function pumpC(data) {
  console.log('the data of pump C is... ', data.toString('utf8'));
}

magicpump(source, concat(pumpA), (err) => {
  magicpump(source, concat(pumpB), (err) => {
    magicpump(source, concat(pumpC), (err) => {
      console.log('all pipes finished', err);
    });
  });
});
```

And all is done! The magic pump will do the work and clone those buffers internally for you, giving the correct data output like this:

```
the data of pump A is...  [content of source stream here]
the data of pump B is...  [content of source stream here]
the data of pump C is...  [content of source stream here]
pipe finished
```