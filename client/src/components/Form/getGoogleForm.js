const { googleFormsToJson } = require('react-google-forms-hooks')
const fs = require('fs')
const path = require('path')

const saveJsonToFile = (filename, json) => {
  const filePath = path.resolve(__dirname, filename)
  fs.writeFile(filePath, JSON.stringify(json), 'utf8', function (err) {
    if (err) throw err
  })
}

const run = async () => {
  const result = await googleFormsToJson(
    'https://docs.google.com/forms/d/1SRzbdxf8YRV6bkOJZlBdMIyLvLr0RmGoETp0zLc5STw/viewform'
  )
  saveJsonToFile('form.json', result)
}

run()