const express = require('express')
const routes = require('./routes')
const path = require('path')


const app = express()



app.set('view engine', 'ejs')
app.set('views', path.join(__dirname, 'views'))



app.get('/', routes);
app.post('/register', routes)
app.get('/login', routes)
app.post('/login', routes)
app.get('/success', routes)
app.get('/logout', routes)
app.post('/addmsg', routes)

const PORT = process.env.PORT || 5000

app.listen(PORT, () => console.log('connected', PORT))