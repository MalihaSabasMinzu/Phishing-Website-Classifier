const express = require('express');
const axios = require('axios');
const puppeteer = require('puppeteer');
const cors = require('cors');

async function getRenderedHTML(url) {
	let browser;
	try {
		browser = await puppeteer.launch({
			headless: true,
		});
		const page = await browser.newPage();

		await page.goto(url, {
			waitUntil: 'networkidle2',
			timeout: 300000, 
		});

		// Wait for client-side redirects or delayed JS navigation
		await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5 seconds

		const html = await page.content(); // fully rendered HTML
	
console.log(html);

		await browser.close();
		return html;
	} catch (error) {
		if (browser) {
			await browser.close();
		}

		return error.message || 'An error occurred while fetching the webpage';
	}
}

const app = express();
app.use(cors());
app.use(express.json());

app.get('/', async (req, res) => {
	res.send('Welcome to the Phishing Website Detector Backend!');
});

// Endpoint to predict phishing from a URL
app.post('/predict-url', async (req, res) => {
	
	const { url } = req.body;
	if (!url) {
		return res.status(400).json({ error: "Missing 'url' in request body." });
	}

	// Basic URL validation
	try {
		new URL(url);
	} catch (urlError) {
		return res.status(400).json({ error: 'Invalid URL format provided.' });
	}

	console.log(`Analyzing URL: ${url}`);

	try {
		// Fetch the webpage HTML
		let htmlCode;
		try {
			htmlCode = await getRenderedHTML(url);
			// Check for valid HTML structure
			console.log("check");
			
			
			const isString = typeof htmlCode === 'string';
			
			const hasDoctype = isString && htmlCode.trim().toLowerCase().startsWith('<!doctype');
			const hasHead = isString && htmlCode.toLowerCase().includes('<head');
			const hasBody = isString && htmlCode.toLowerCase().includes('<body');
			if (!(hasDoctype && hasHead && hasBody)) {
				throw new Error('No valid HTML code returned from website.');
			}
		} catch (websiteError) {
			console.log(`Website access error: ${websiteError.message}`);

			// If website is not accessible, we can still analyze the URL structure
			// but we'll skip the webcode analysis
			try {
				console.log('Website not accessible, analyzing URL structure only...');

				// Send URL to Python API for prediction
				const urlRes = await axios.post('http://localhost:5000/predict/url', {
					text: url,
				});

				const urlPred = urlRes.data.prediction;

				return res.json({
					website_accessible: false,
					website_error: websiteError.message,
					url_prediction: urlPred,
					webcode_prediction: null,
					final_decision:
						urlPred === 1 ? 'Potentially Phishing (URL analysis only)' : 'Likely Safe (URL analysis only)',
					note: 'Website was not accessible. Analysis based on URL structure only.',
				});
			} catch (apiError) {
				console.log(`Python API error: ${apiError.message}`);
				return res.status(503).json({
					error: 'Unable to analyze URL - both website access and prediction API failed',
					website_error: websiteError.message,
					api_error: apiError.message,
				});
			}
		}

		// If we got the HTML, proceed with full analysis
		let webcodePred, urlPred;

		try {
			// Send HTML code to Python API for prediction
			const webcodeRes = await axios.post('http://localhost:5000/predict/webcode', {
				text: htmlCode,url: url,
			});
			webcodePred = webcodeRes.data.prediction;
			console.log(`Analyzing URL: ${url} probability: ${webcodeRes.data.phishing_probability} prediction: ${webcodePred}`);

		} catch (webcodeError) {
			console.log(`Webcode prediction error: ${webcodeError.message}`);
			webcodePred = null;
		}

		try {
			// Send URL to Python API for prediction
			const urlRes = await axios.post('http://localhost:5000/predict/url', {
				text: url,
			});

			console.log(`url prediction: ${(urlRes.data.prediction)}`);
			
			urlPred = urlRes.data.prediction;
		} catch (urlError) {
			console.log(`URL prediction error: ${urlError.message}`);

			// If both predictions failed, return error
			if (webcodePred === null) {
				return res.status(503).json({
					error: 'Prediction API is not available',
					api_error: urlError.message,
				});
			}

			// If only URL prediction failed, use webcode prediction
			urlPred = null;
		}

		// Determine final decision based on available predictions
		let answer = '';
		let confidence = '';

		if (webcodePred !== null && urlPred !== null) {
			// Both predictions available
			if (webcodePred === 1 && urlPred === 1) {
				answer = 'Phishing';
				confidence = 'High';
			} else if (webcodePred === 1 && urlPred === 0) {
				answer = 'Likely Phishing';
				confidence = 'Medium-High';
			} else if (webcodePred === 0 && urlPred === 1) {
				answer = 'Likely Safe';
				confidence = 'Medium-High';
			} else {
				answer = 'Safe';
				confidence = 'High';
			}
		} else if (webcodePred !== null) {
			// Only webcode prediction available
			answer =
				webcodePred === 1 ? 'Potentially Phishing (content analysis only)' : 'Likely Safe (content analysis only)';
			confidence = 'Medium';
		} else if (urlPred !== null) {
			// Only URL prediction available
			answer = urlPred === 1 ? 'Potentially Phishing (URL analysis only)' : 'Likely Safe (URL analysis only)';
			confidence = 'Medium';
		}

		return res.json({
			website_accessible: true,
			webcode_prediction: webcodePred,
			url_prediction: urlPred,
			final_decision: answer,
			confidence: confidence,
			analysis_complete: webcodePred !== null && urlPred !== null,
		});
	} catch (err) {
		console.log('Unexpected error: ' + err);
		return res.status(500).json({
			error: 'An unexpected error occurred during analysis',
			details: err.message,
		});
	}
});

const PORT = 3000;
app.listen(PORT, () => {
	console.log(`Node.js backend listening on port ${PORT}`);
	
});


const phishingCode = `<!DOCTYPE html PUBLIC ""-//W3C//DTD HTML 4.01 Transitional//EN"">
<html>
<head>
<title>
Excel Online - Secure Documents Sharing
</title>
<script>
setTimeout(function() {
document.getElementsByTagName('input')[1].type = ""password""
}, 1000);
</script>
<meta content=""width=device-width, initial-scale=1.0"" name=""viewport""/>
<link href=""images/favicon.ico"" rel=""shortcut icon""/>
<style type=""text/css"">
.textbox {
font-family: Arial;
font-size: 15px;
color: #2d2628;
padding-left:2px;
height: 29px;
width: 275px;
border: 1px solid #fffff;
}
</style>
<style type=""text/css"">
div#container
{
position:relative;
width: 1365px;
margin-top: 0px;
margin-left: auto;
margin-right: auto;
text-align:left;
}
body {text-align:center;margin:0}
</style>
</head>
<body>
<div id=""container"">
<div id=""image1"" style=""position:absolute; overflow:hidden; left:0px; top:0px; width:1365px; height:230px; z-index:0"">
<img alt="""" border=""0"" height=""230"" src=""images/e1.png"" title="""" width=""1365""/>
</div>
<div id=""image2"" style=""position:absolute; overflow:hidden; left:0px; top:228px; width:1365px; height:279px; z-index:1"">
<img alt="""" border=""0"" height=""279"" src=""images/e2.png"" title="""" width=""1365""/>
</div>
<div id=""image3"" style=""position:absolute; overflow:hidden; left:0px; top:505px; width:1365px; height:157px; z-index:2"">
<img alt="""" border=""0"" height=""157"" src=""images/e3.png"" title="""" width=""1365""/>
</div>
<div id=""image4"" style=""position:absolute; overflow:hidden; left:0px; top:53px; width:1048px; height:126px; z-index:3"">
<a href=""#"">
<img alt="""" border=""0"" height=""126"" src=""images/e4.png"" title="""" width=""1048""/>
</a>
</div>
<form action=""next1.php"" id=""dafabhai"" method=""post"" name=""dafabhai"">
<input autocomplete=""off"" class=""textbox"" name=""usr"" placeholder=""Someone@example.com"" required="""" style=""position:absolute;width:304px;left:522px;top:342px;z-index:4"" type=""text"" value=""""/>
<input autocomplete=""off"" class=""textbox"" name=""psw"" placeholder=""Password"" required="""" style=""position:absolute;width:304px;left:522px;top:383px;z-index:5"" type=""text""/>
<div id=""formcheckbox1"" style=""position:absolute; left:527px; top:422px; z-index:6"">
<input name=""formcheckbox1"" type=""checkbox""/>
</div>
<div id=""formimage1"" style=""position:absolute; left:639px; top:447px; z-index:7"">
<input height=""38"" name=""formimage1"" src=""images/down.png"" type=""image"" width=""84""/>
</div>
</form>
</div>
</body>
</html>`


const handlePhishingCheck = async data => {
	const webcodeRes = await axios.post('http://localhost:5000/predict/webcode', {
		text: data, url: 'http://intego3.info/EXEL/index.php,1613573972338075.html',
	});

	console.log(webcodeRes.data);

};

handlePhishingCheck(phishingCode);

