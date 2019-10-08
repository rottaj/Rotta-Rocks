import React from 'react'
import Card from '@material-ui/core/Card';
import CardActions from '@material-ui/core/CardActions';
import CardHeader from '@material-ui/core/CardHeader'
import CardContent from '@material-ui/core/CardContent';
import Button from '@material-ui/core/Button';
import Typography from 'material-ui/styles/typography';

const styles = {
  card: {
    margin: '10%',  // 16px
    minWidth: 275,
    padding: '50%',   // 10px
    'text-decoration': 'none'
  },
  title: {
    fontSize: 14,
    'text-align': 'center'
  },
  pos: {
    padding: '30px'
  },
};


const StarRepo = (props) => (
    <div>
        {console.log(props.repo)}
        <a href={props.repo.html_url}>
        <Card className="starRepo" style={{ ...styles.card,  ...styles.pos}}>
            <CardContent component="h2">
                {props.repo.name}
            </CardContent>
            <CardContent>
                Language: {props.repo.language}
            </CardContent>
            <CardContent>
              {props.repo.description}
            </CardContent>
        </Card>
        </a>
    </div>
)

export default StarRepo;