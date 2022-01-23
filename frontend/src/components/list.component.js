import React, { Component } from "react";
import axios from "axios";

import { Container,TableContainer, Table, TableHead, TableRow, TableCell,TableBody,Paper } from "@mui/material";

const User = (props) => (
  <TableRow
>
<TableCell>{props.user.fullname}</TableCell>
<TableCell>{props.user.email}</TableCell>
<TableCell>{getDateString(props.user.createdAt)}</TableCell>
    </TableRow>
);

function getDateString(reqdate) {
  var days = 0;
  var hours = 0;
  var minutes = 0;
  var time = 0;
  time = new Date() - new Date(reqdate);
  //console.log("req " +time)
  if (time / (1000 * 60 * 60 * 24) > 0) {
    days = Math.trunc(time / (1000 * 60 * 60 * 24));
    time = time - days * (1000 * 60 * 60 * 24);
  }
  if (time / (1000 * 60 * 60) > 0) {
    hours = Math.trunc(time / (1000 * 60 * 60));
    time = time - hours * (1000 * 60 * 60);
  }
  if (time / (1000 * 60) > 0) {
    minutes = Math.trunc(time / (1000 * 60));
  }

  var calculation = (
    (days !== 0 ? days + " days " : "") +
    (hours !== 0 ? hours + " hours " : "") +
    (minutes !== 0 ? minutes + " minutes " : "less than a minute")
  ).trim();
  return (calculation.length > 0 ? calculation : "less than a minute") + " ago";
}

const baseURL = "http://localhost:3002/users";

export default class List extends Component {
  constructor(props) {
    super(props);
    this.state = {
      users: []
  };
  }
  componentDidMount() {
    this.TryToGetUsers();
  }

  TryToGetUsers() {
    const token = localStorage.getItem("verySecureJWT");
    const auth = localStorage.getItem("Authorization");
    if (!token) {
      window.location = "/login";
      return;
    }
    axios
      .post(
        `${baseURL}/list`,
        {
          token: token,
          Authorization: auth
        },
        {
          headers: {
            "Content-type": "application/json; charset=UTF-8",
          },
          withCredentials : true
        }
      )
      .then((json) => {
        console.log(json.data.data);
        if(json.data.data.length>0){
          this.setState({ users: json.data.data })
      }else{
          this.setState({ users: [] })
      }
      })
      .catch((err) => {
        if(err.response.status===401){
          window.location="/login"
        }
      });
  }
  userList() {
    return this.state.users.reverse().map(currentuser => {
      return <User user={currentuser} key={currentuser._id}/>;
    })
  }
  changeResult = (resultText) => {
    this.setState({ resultvalue: resultText });
  };
  render() {
    return (
      <div>
        <div className="App">
          <Container maxWidth="sm">
        <TableContainer component={Paper}>
      <Table sx={{ minWidth: 650 }} aria-label="simple table">
        <TableHead>
          <TableRow>
            <TableCell>Name</TableCell>
            <TableCell>Email</TableCell>
            <TableCell>Register Time</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
        { this.userList() }
        </TableBody>
      </Table>
    </TableContainer>
    </Container>
        </div>
      </div>
    );
  }
}
