const express = require('express');
const sql = require("mssql");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const axios = require('axios');
const dotenv = require('dotenv');
const multer = require('multer');
const path = require('path');
const FormData = require('form-data');

const IMGUR_CLIENT_ID = process.env.IMGUR_CLIENT_ID;

dotenv.config(); // Load environment variables

// App setup
const app = express();
const port = process.env.PORT || 4848;

// JWT Secret for Authentication
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware setup
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
	secret: JWT_SECRET,
	resave: false,
	saveUninitialized: true,
	cookie: { secure: false } // Make secure in production with HTTPS
}));

// SQL Server config
const config = {
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    server: process.env.DB_SERVER,
    database: process.env.DB_DATABASE,
    port: parseInt(process.env.DB_PORT) || 1433,
    options: {
        trustServerCertificate: true
    }
};

// Set up multer for file storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); // Files will be stored in an "uploads" directory
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); // Name the file uniquely
  },
});

// Create the upload object using the defined storage
const upload = multer({ storage: storage });

// Middleware to serve static files (images)
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


// Connect to MSSQL Database
sql.connect(config)
	.then(pool => {
		console.log('Connected to SQL Server database');

		// Server listener
		app.listen(port, () => {
			console.log(`Server running at http://localhost:${port}`);
		});

		// Define your routes below
		// For example:
		app.get('/', (req, res) => {
			res.send('Hello from Node.js Server');
		});
		
		app.get('/api/users', async (req, res) => {
			try {
				const result = await pool.request().query('SELECT * FROM [USER]');
				res.json(result.recordset);
			} catch (err) {
				console.error('SQL query error:', err);
				res.status(500).send('Error executing query');
			}
		});

		app.post("/api/login", async function(req, res) {
			const { username, password } = req.body;

			try {
				const result = await pool.request()
					.input('username', sql.VarChar, username)
					.query('SELECT * FROM [USER] WHERE USERNAME = @username');

				if (result.recordset.length > 0) {
					const user = result.recordset[0];
					const isPasswordMatch = await bcrypt.compare(password, user.HASHED_PASSWORD);

					if (isPasswordMatch) {
						const userIdFromDatabase = user.USERID;
						const userPayload = { id: userIdFromDatabase };

						// Generate the JWT token with the user info
						const accessToken = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '1h' });

						// Optionally save userId in session if using express-session
						req.session.userId = userIdFromDatabase; // This will only work if you are using sessions effectively

						// Return the access token to the client
						res.status(200).json({
							success: true,
							message: 'Login successful',
							accessToken,
							userId: userIdFromDatabase  // Include userId in the response
						});
					} else {
						res.status(401).json({ success: false, message: 'Invalid username or password' });
					}
				} else {
					res.status(404).json({ success: false, message: 'User not found' });
				}
			} catch (err) {
				console.error('SQL query error:', err);
				res.status(500).send('An unexpected error occurred.');
			}
		});
		
		app.get('/api/checkUser', async (req, res) => {
			const { USERNAME, EMAIL} = req.query;
			
			const trimmedUsername = USERNAME.trim();
			const trimmedEmail = EMAIL.trim();
			
			try {
				const result = await pool.request()
					.input('USERNAME', sql.VarChar, trimmedUsername) // Declare input parameter
					.input('EMAIL', sql.VarChar, trimmedEmail) // Declare input parameter
					.query('SELECT USERNAME, EMAIL FROM [USER] WHERE USERNAME = @USERNAME OR EMAIL = @EMAIL');
				
				// Check if any records were found
				if (result.recordset.length > 0) {
					res.status(409).json({ success: false, message: 'Username or Email is already taken' });
				} else {
					res.status(200).json({ success: true, message: 'Username and Email are available' });
				}
			} catch (err) {
				console.error('SQL query error:', err);
				res.status(500).send('An unexpected error occurred. Please try again later.');
			}
		});
		
		// USER API 
		//Add User
		app.post('/api/addUser', async (req, res) => {
			const { FIRST_NAME, LAST_NAME, MI, USERNAME, PASSWORD, CONTACT_NUMBER, EMAIL, BIRTHDATE, PICTURE } = req.body;

			try {
				const saltRounds = 10;
				const hashedPassword = await bcrypt.hash(PASSWORD, saltRounds);
				// Execute the SQL stored procedure to insert the new user
				const result = await pool.request()
					.input('FIRST_NAME', sql.VarChar, FIRST_NAME)
					.input('LAST_NAME', sql.VarChar, LAST_NAME)
					.input('MI', sql.VarChar, MI)
					.input('USERNAME', sql.VarChar, USERNAME)
					.input('CONTACT_NUMBER', sql.VarChar, CONTACT_NUMBER)
					.input('EMAIL', sql.VarChar, EMAIL)
					.input('BIRTHDATE', sql.VarChar, BIRTHDATE)
					.input('PICTURE', sql.VarChar, PICTURE)
					.input('HASHED_PASSWORD', sql.VarChar, hashedPassword)  // Store the hashed password
					.execute('SP_INSERT_USER');

				// Send success response only if the execution was successful
				res.status(201).json({ success: true, message: 'User registered successfully' });
			} catch (err) {
				console.error('Error registering user:', err);
				res.status(500).json({ success: false, message: 'An unexpected error occurred. Please try again later.' });
			}
		});
		
		//Update User
		app.put('/api/updateUser/:username', async (req, res) => {
			const { FIRST_NAME, LAST_NAME, MI, CONTACT_NUMBER, EMAIL, BIRTHDATE, PICTURE, PASSWORD } = req.body;

			try {
				const request = pool.request();
				request.input('USERNAME', sql.VarChar, req.params.username)
						.input('FIRST_NAME', sql.VarChar, FIRST_NAME)
						.input('LAST_NAME', sql.VarChar, LAST_NAME)
						.input('MI', sql.VarChar, MI)
						.input('CONTACT_NUMBER', sql.VarChar, CONTACT_NUMBER)
						.input('EMAIL', sql.VarChar, EMAIL)
						.input('BIRTHDATE', sql.VarChar, BIRTHDATE)
						.input('PICTURE', sql.VarChar, PICTURE);

				if (PASSWORD) {
					const saltRounds = 10;
					const hashedPassword = await bcrypt.hash(PASSWORD, saltRounds);
					request.input('NEW_HASHED_PASSWORD', sql.VarChar, hashedPassword); // Use the optional hashed password parameter
				} else {
					request.input('NEW_HASHED_PASSWORD', sql.VarChar, null); // If no password is provided, pass NULL
				}

				request.execute('SP_UPDATE_USER', (err, result) => {
					if (err) {
						console.error('Error executing SP_UPDATE_USER:', err);
						res.status(500).json({ error: 'Error executing SP_UPDATE_USER' });
						return;
					}
					res.status(200).json({ success: true, message: 'Updated user information successfully' });
				});
			} catch (err) {
				console.error('Error updating user:', err);
				res.status(500).json({ success: false, message: 'An unexpected error occurred. Please try again later.' });
			}
		});
		
		//Update User in Profile Fragment
		app.put('/api/updateUser2/:email', async (req, res) => {
			const { FIRST_NAME, LAST_NAME, MI, CONTACT_NUMBER, BIRTHDATE, PICTURE, EMAIL, USERNAME } = req.body;

			try {
				const request = pool.request();
				request.input('USERNAME', sql.VarChar, USERNAME)
						.input('FIRST_NAME', sql.VarChar, FIRST_NAME)
						.input('LAST_NAME', sql.VarChar, LAST_NAME)
						.input('MI', sql.VarChar, MI)
						.input('CONTACT_NUMBER', sql.VarChar, CONTACT_NUMBER)
						.input('BIRTHDATE', sql.VarChar, BIRTHDATE)
						.input('PICTURE', sql.VarChar, PICTURE)
						.input('EMAIL', sql.VarChar, req.params.email);

				request.execute('SP_UPDATE_USER_2', (err, result) => {
					if (err) {
						console.error('Error executing SP_UPDATE_USER:', err);
						res.status(500).json({ error: 'Error executing SP_UPDATE_USER_2' });
						return;
					}
					res.status(200).json({ success: true, message: 'Updated user information successfully' });
				});
			} catch (err) {
				console.error('Error updating user:', err);
				res.status(500).json({ success: false, message: 'An unexpected error occurred. Please try again later.' });
			}
		});
		
		//Delete user
		app.delete('/api/deleteUser/:id', async (req, res) => {
			const userId = req.params.id;
			try {
				await pool.request()
					.input('USERID', sql.Int, userId)
					.execute('SP_DELETE_USER');
				res.status(200).json({ success: true, message: 'User deleted successfully' });
			} catch (err) {
				console.error('Error deleting user:', err);
				res.status(500).json({ success: false, message: 'An unexpected error occurred. Please try again later.' });
			}
		});
		
		//Fetch User Details
		app.get('/api/fetchUser/:id', async (req, res) => {
			const userId = req.params.id;
			try {
				const result = await pool.request()
					.input('userId', sql.NVarChar, userId)
					.query("SELECT * FROM [USER] WHERE USERID = @userId");
				if (result.recordset.length > 0) {
					res.json(result.recordset[0]);
				} else {
					res.status(404).json({ error: 'User not found' });
				}
			} catch (error) {
				console.error('Error fetching user:', error);
				res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
			}
		});
		
		//FAMILY API
		//Add Family
		app.post('/api/addFamily', async (req, res) => {
			try {
				const familyResult = await pool.request()
					.execute('SP_INSERT_FAMILY');

				const FAMILYID = familyResult.recordset[0].FAMILYID;
				res.status(201).json({ success: true, FAMILYID, message: 'Family added successfully', FAMILYID });
			} catch (err) {
				console.error('Error adding family:', err);
				res.status(500).json({ success: false, message: 'An unexpected error occurred. Please try again later.' });
			}
		});
		
		//Add Family Members
		app.post('/api/addFamilyMember', async (req, res) => {
			const { FAMILYID, MEMBERNAME, RELATIONSHIP } = req.body;

			try {
				await pool.request()
					.input('FAMILYID', sql.Int, FAMILYID)
					.input('MEMBERNAME', sql.VarChar, MEMBERNAME)
					.input('RELATIONSHIP', sql.VarChar, RELATIONSHIP)
					.execute('SP_INSERT_FAMILYMEMBERS');

				res.status(201).json({ success: true, message: 'Family member added successfully' });
			} catch (err) {
				console.error('Error adding family member:', err);
				res.status(500).json({ success: false, message: 'An unexpected error occurred. Please try again later.' });
			}
		});
		
		//Retrieve Family Members
		app.get('/api/fetchFamily/:id', async (req, res) => {
			const membersId = req.params.id;
			try {
				const result = await pool.request()
					.input('membersId', sql.Int, membersId)
					.query("SELECT * FROM FAMILYMEMBERS WHERE FAMILYID = @membersId");
				
				if (result.recordset.length > 0) {
					// Return all family members
					res.json(result.recordset);
				} else {
					res.status(404).json({ error: 'Family not found' });
				}
			} catch (error) {
				console.error('Error fetching family:', error);
				res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
			}
		});
		
		//GALLERY API
		app.post('/api/addGallery', async (req, res) => {
			try {
				const galleryResult = await pool.request()
					.execute('SP_INSERT_GALLERY');

				const GALLERYID = galleryResult.recordset[0].GALLERYID;
				res.status(201).json({ success: true, GALLERYID, message: 'Gallery added successfully', GALLERYID });
			} catch (err) {
				console.error('Error adding gallery:', err);
				res.status(500).json({ success: false, message: 'An unexpected error occurred. Please try again later.' });
			}
		});
		
		app.post('/api/addGalleryMedia', async (req, res) => {
			const { GALLERYID, MEDIATYPE, FILENAME } = req.body;

			try {
				await pool.request()
					.input('GALLERYID', sql.Int, GALLERYID)
					.input('MEDIATYPE', sql.VarChar, MEDIATYPE)
					.input('FILENAME', sql.VarChar, FILENAME)
					.execute('SP_INSERT_GALLERY_MEDIA');

				res.status(201).json({ success: true, message: 'Gallery media added successfully' });
			} catch (err) {
				console.error('Error adding gallery media:', err);
				res.status(500).json({ success: false, message: 'An unexpected error occurred. Please try again later.' });
			}
		});
		
		//Retrieve gallery
		app.get('/api/fetchGallery/:id', async (req, res) => {
			const galleryId = req.params.id;
			try {
				const result = await pool.request()
					.input('galleryId', sql.Int, galleryId)
					.query("SELECT * FROM GALLERYMEDIA WHERE GALLERYID = @galleryId");
				
				if (result.recordset.length > 0) {
					res.json(result.recordset);
				} else {
					res.status(404).json({ error: 'Gallery not found' });
				}
			} catch (error) {
				console.error('Error fetching gallery:', error);
				res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
			}
		});

		//OBITUARY API
		//Fetch Obituary Details
		app.get('/api/fetchObit/:id', async (req, res) => {
			const obitId = req.params.id;
			try {
				const result = await pool.request()
					.input('obitId', sql.Int, obitId)
					.query("SELECT * FROM OBITUARY AS O INNER JOIN OBITUARY_CUSTOMIZATION AS OC ON O.OBITCUSTID = OC.OBITCUSTID WHERE OBITUARYID = @obitId");
				if (result.recordset.length > 0) {
					res.json(result.recordset[0]);
				} else {
					res.status(404).json({ error: 'Obituary not found' });
				}
			} catch (error) {
				console.error('Error fetching obituary:', error);
				res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
			}
		});
		
		//Add Obituary
		app.post('/api/addObituary', async (req, res) => {
			const { USERID, GALLERYID, OBITCUSTID, FAMILYID, BIOGRAPHY, OBITUARYNAME, OBITUARYPHOTO, DATEOFBIRTH, DATEOFDEATH, KEYEVENTS, OBITUARYTEXT, FUNDATETIME, FUNLOCATION, ADTLINFO, FAVORITEQUOTE, PRIVACY, ENAGUESTBOOK } = req.body;

			try {
				const result = await pool.request()
					.input('USERID', sql.Int, USERID)
					.input('GALLERYID', sql.Int, GALLERYID)
					.input('FAMILYID', sql.Int, FAMILYID)
					.input('OBITCUSTID', sql.Int, OBITCUSTID)
					.input('BIOGRAPHY', sql.VarChar, BIOGRAPHY)
					.input('OBITUARYNAME', sql.VarChar, OBITUARYNAME)
					.input('OBITUARYPHOTO', sql.NVarChar, OBITUARYPHOTO)
					.input('DATEOFBIRTH', sql.Date, DATEOFBIRTH)
					.input('DATEOFDEATH', sql.Date, DATEOFDEATH)
					.input('KEYEVENTS', sql.VarChar, KEYEVENTS)
					.input('OBITUARYTEXT', sql.VarChar, OBITUARYTEXT)
					.input('FUN_DATETIME', sql.DateTime, FUNDATETIME)
					.input('FUN_LOCATION', sql.VarChar, FUNLOCATION)
					.input('ADTLINFO', sql.VarChar, ADTLINFO)
					.input('FAVORITEQUOTE', sql.VarChar, FAVORITEQUOTE)
					.input('PRIVACY', sql.VarChar, PRIVACY)
					.input('ENAGUESTBOOK', sql.Bit, ENAGUESTBOOK)
					.execute('SP_INSERT_OBITUARY');

				res.status(201).json({ success: true, message: 'Obituary registered successfully' });
			} catch (err) {
				console.error('Error registering obituary:', err);
				res.status(500).json({ success: false, message: 'An unexpected error occurred. Please try again later.' });
			}
		});
		
		//Delete Obituary
		app.delete('/api/deleteObituary/:id', async (req, res) => {
			const obituaryId = req.params.id;
			try {
				await pool.request()
					.input('OBITUARYID', sql.Int, obituaryId)
					.execute('SP_DELETE_OBITUARY');
				res.status(200).json({ success: true, message: 'Obituary deleted successfully' });
			} catch (err) {
				console.error('Error deleting obituary:', err);
				res.status(500).json({ success: false, message: 'An unexpected error occurred. Please try again later.' });
			}
		});
		
		//OBITUARY_CUSTOMIZATION API
		//Add Obituary_Customization
		app.post('/api/addObituaryCust', async (req, res) => {
			const { BGTHEME, PICFRAME, BGMUSIC, VFLOWER, VCANDLE } = req.body;

			try {
				const result = await pool.request()
					.input('BGTHEME', sql.VarChar, BGTHEME)
					.input('PICFRAME', sql.VarChar, PICFRAME)
					.input('BGMUSIC', sql.VarChar, BGMUSIC)
					.input('VFLOWER', sql.VarChar, VFLOWER)
					.input('VCANDLE', sql.VarChar, VCANDLE)
					.execute('SP_INSERT_OBITUARY_CUSTOMIZATION');

				const obitCustId = result.recordset[0].OBITCUSTID;
				res.status(201).json({ success: true, obitCustId, message: 'Obituary Customization registered successfully' });
			} catch (err) {
				console.error('Error registering obituary customization:', err);
				res.status(500).json({ success: false, message: 'An unexpected error occurred. Please try again later.' });
			}
		});
		
		//RETRIEVE OBITUARIES
		app.get('/api/allObit', async (req, res) => {
			try {
				const result = await pool.request()
					.query('SELECT * FROM OBITUARY WHERE PRIVACY = \'Public\'');
				res.json(result.recordset);
			} catch (error) {
				console.error('Error fetching obituaries:', error);
				res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
			}
		});
		
		//RETRIEVE OBITUARIES BY USER
		app.get('/api/allObitByUser/:id', async (req, res) => {
			const userId = req.params.id;
			try {
				const result = await pool.request()
					.input('userId', userId)
					.query('SELECT * FROM OBITUARY WHERE USERID = @userId'); // Filter by USERID
				res.json(result.recordset);
			} catch (error) {
				console.error('Error fetching obituaries:', error);
				res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
			}
		});
		
		//GUESTBOOK API
		//Add Guestbook
		app.post('/api/addGuestBook', async (req, res) => {
			const { USERID, OBITUARYID, GUESTNAME, MESSAGE } = req.body;

			try {
				const result = await pool.request()
					.input('USERID', sql.Int, USERID)
					.input('OBITUARYID', sql.Int, OBITUARYID)
					.input('GUESTNAME', sql.VarChar, GUESTNAME)
					.input('MESSAGE', sql.VarChar, MESSAGE)
					.execute('SP_INSERT_GUESTBOOK');

				const guestbookId = result.recordset[0].GUESTBOOKID;
				res.status(201).json({ success: true, guestbookId, message: 'Guestbook registered successfully' });
			} catch (err) {
				console.error('Error registering guestbook:', err);
				res.status(500).json({ success: false, message: 'An unexpected error occurred. Please try again later.' });
			}
		});
		
		//Update Guestbook
		app.put('/api/updateGuestbook/:guestbookId', async (req, res) => {
			const { USERID, OBITUARYID, GUESTNAME, MESSAGE } = req.body;

			try {
				const request = pool.request();
				request.input('USERID', sql.Int, USERID)
						.input('OBITUARYID', sql.Int, OBITUARYID)
						.input('GUESTNAME', sql.VarChar, GUESTNAME)
						.input('MESSAGE', sql.VarChar, MESSAGE);

				request.execute('SP_UPDATE_GUESTBOOK', (err, result) => {
					if (err) {
						console.error('Error executing SP_UPDATE_GUESTBOOK:', err);
						res.status(500).json({ error: 'Error executing SP_UPDATE_GUESTBOOK' });
						return;
					}
					res.status(200).json({ success: true, message: 'Updated guestbook successfully' });
				});
			} catch (err) {
				console.error('Error updating guestbook:', err);
				res.status(500).json({ success: false, message: 'An unexpected error occurred. Please try again later.' });
			}
		});
		
		//Retrieve Guestbook
		app.get('/api/allGuestbook', async (req, res) => {
			const { OBITUARYID } = req.query;
			
			try {
				const result = await pool.request()
					.input('OBITUARYID', sql.Int, OBITUARYID)
					.query('SELECT G.GUESTBOOKID, G.USERID, G.OBITUARYID, G.GUESTNAME, G.MESSAGE, G.POSTINGDATE, U.PICTURE, U.FIRST_NAME, U.MI, U.LAST_NAME FROM GUESTBOOK AS G INNER JOIN [USER] AS U ON U.USERID = G.USERID WHERE OBITUARYID = @OBITUARYID');
				res.json(result.recordset);
			} catch (error) {
				console.error('Error fetching guestbook:', error);
				res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
			}
		});
		
		
		//TRIBUTE API
		//Add Tribute
		app.post('/api/addTribute', async (req, res) => {
			const { USERID, OFFEREDCANDLE, LIGHTEDCANDLE } = req.body;

			try {
				const result = await pool.request()
					input('USERID', sql.Int, USERID)
					.input('OFFEREDFLOWER', sql.VarChar, OFFEREDFLOWER)
					.input('LIGHTEDCANDLE', sql.VarChar, LIGHTEDCANDLE)
					.execute('SP_INSERT_TRIBUTE');

				const tributeId = result.recordset[0].TRIBUTEID;
				res.status(201).json({ success: true, guestbookId, message: 'Tribute registered successfully' });
			} catch (err) {
				console.error('Error registering tribute:', err);
				res.status(500).json({ success: false, message: 'An unexpected error occurred. Please try again later.' });
			}
		});
		
		//Update Tribute
		app.put('/api/updateTribute/:tributeId', async (req, res) => {
			const { USERID, OFFEREDCANDLE, LIGHTEDCANDLE } = req.body;

			try {
				const request = pool.request();
				request.input('USERID', sql.Int, USERID)
						.input('OFFEREDFLOWER', sql.VarChar, OFFEREDFLOWER)
						.input('LIGHTEDCANDLE', sql.VarChar, LIGHTEDCANDLE);

				request.execute('SP_UPDATE_TRIBUTE', (err, result) => {
					if (err) {
						console.error('Error executing SP_UPDATE_TRIBUTE:', err);
						res.status(500).json({ error: 'Error executing SP_UPDATE_TRIBUTE' });
						return;
					}
					res.status(200).json({ success: true, message: 'Updated tribute successfully' });
				});
			} catch (err) {
				console.error('Error updating tribute:', err);
				res.status(500).json({ success: false, message: 'An unexpected error occurred. Please try again later.' });
			}
		});
		
		
		//IMAGE UPLOADING TO LOCAL SERVER
		app.post('/api/uploadImage', upload.single('image'), (req, res) => {
			if (req.file) {
				const imageUrl = `http://localhost:${port}/uploads/${req.file.filename}`;
				res.status(200).json({ success: true, imageUrl });
			} else {
				res.status(400).json({ success: false, message: 'Failed to upload image' });
			}
		});
	})
	.catch(error => {
		console.error('Error connecting to SQL Server database:', error);
	});

// Global Error Listener
sql.on('error', err => {
    console.error('SQL Server Pool Error:', err);
});

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
	const authHeader = req.headers['authorization'];
	const token = authHeader && authHeader.split(' ')[1];
	if (!token) return res.sendStatus(401);

	jwt.verify(token, 'memoreal_secret', (err, user) => {
		if (err) return res.sendStatus(403);
		req.userId = user.id;
		next();
	});
};

// Video Generation Endpoint (using D-id API)
const DID_API_KEY = process.env.DID_API_KEY;
const BASE_URL = 'https://api.d-id.com/talks/';

//UPLOADING IMAGE TO IMGUR USING API
app.post('/api/uploadImageToImgur', async (req, res) => {
	const imagePath = req.body.imagePath; // This should be the path of the image you saved to internal storage

	if (!imagePath || !fs.existsSync(imagePath)) {
		return res.status(400).json({ success: false, message: 'Invalid image path' });
	}

	try {
		const form = new FormData();
		form.append('image', fs.createReadStream(imagePath));

		const response = await axios.post('https://api.imgur.com/3/image', form, {
			headers: {
				'Authorization': `Client-ID ${IMGUR_CLIENT_ID}`,
				...form.getHeaders()
			}
		});

		if (response.data.success) {
			const imageUrl = response.data.data.link;
			console.log('Image uploaded to Imgur: ', imageUrl);
			res.status(200).json({ success: true, imageUrl });
		} else {
			res.status(500).json({ success: false, message: 'Failed to upload image to Imgur' });
		}
	} catch (error) {
		console.error('Error uploading to Imgur: ', error.message);
		res.status(500).json({ success: false, message: 'Error uploading image to Imgur' });
	}
});

//GENERATE AI VIDEO FROM D-ID AI
app.post('/api/generateVideo', async (req, res) => {
	const { prompt, voiceId, sourceUrl } = req.body;

	if (!prompt || !voiceId || !sourceUrl) {
		return res.status(400).json({ success: false, message: 'Missing parameters' });
	}

	try {
		// Update endpoint to match the example from the screenshot.
		const response = await axios.post(
			BASE_URL,
			{
				script: {
					type: 'text',
					input: prompt,
					provider: {
						type: 'microsoft',
						voice_id: voiceId
					}
				},
				source_url: sourceUrl
			},
			{
				headers: {
					'Content-Type': 'application/json',
					'Authorization': `Basic ${DID_API_KEY}`,
				},
			}
		);

		console.log('Video Generation Response:', response.data);
		res.status(200).json({ success: true, data: response.data });

	} catch (error) {
		console.error('Error generating video:', error.response ? error.response.data : error.message);
		res.status(500).json({ success: false, message: 'Error generating video' });
	}
});

app.get('/api/retrieveImage/:imageId', async (req, res) => {
    const { imageId } = req.params;

    if (!imageId) {
        return res.status(400).json({ success: false, message: 'Missing image ID' });
    }

    try {
        const response = await axios.get(`https://api.imgur.com/3/image/${imageId}`, {
            headers: {
                'Authorization': `Client-ID ${IMGUR_CLIENT_ID}`
            }
        });

        console.log('Imgur Retrieve Response:', response.data);
        res.status(200).json({ success: true, data: response.data });
    } catch (error) {
        console.error('Error retrieving image from Imgur:', error.response ? error.response.data : error.message);
        res.status(500).json({ success: false, message: 'Error retrieving image from Imgur' });
    }
});

//GET THE VIDEO FROM THE GENERATE API
app.get('/api/retrieveVideo/:videoId', async (req, res) => {
    const { videoId } = req.params;

    if (!videoId) {
        return res.status(400).json({ success: false, message: 'Missing video ID' });
    }

    try {
        const response = await axios.get(`${BASE_URL}${videoId}`, {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Basic ${DID_API_KEY}`,
            },
        });

        console.log('Retrieve Video Response:', response.data);
        res.status(200).json({ success: true, data: response.data });

    } catch (error) {
        console.error('Error retrieving video:', error.response ? error.response.data : error.message);
        res.status(500).json({ success: false, message: 'Error retrieving video' });
    }
});