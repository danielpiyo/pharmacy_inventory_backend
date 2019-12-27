router.get('/questionsiquiz/:sqh_id', function (req, res) {
       
        console.log('req', req);
        connection.execute(
            'select sqh_id, ' +
            'quiz_number, ' +
            'revision_type_yn, ' +
            'subject_code \n' +
            'from iquiz.iq_student_quiz_headers \n' +
            'where sqh_id = :sqh_id',
            {
                sqh_id: req.params.sqh_id
            },
            function (err, results) {
                var sqheaders = {};
                if (err) {
                    // throw err;
                    console.error(err.message);
                }
                console.log('results', results);
                sqheaders.id = results.rows[0][0];
                sqheaders.number = results.rows[0][1];
                sqheaders.secondary = results.rows[0][2];
                sqheaders.description = results.rows[0][3];
                res.set('Content-Type', 'application/json');
                listquestions(sqheaders, connection, res);
                //getquestiondetails (sqheaders, connection,res);
            }
        ); // end execute ...
    
});


function listquestions(sqheaders, connection, res) {
    connection.execute(
        'select sqq_id, \n' +
        '  question_number, ' +
        '  questionTypeId, ' +
        '   image_link, ' +
        '   answer_narration, ' +
        '   answer_image_link, ' +
        '   passage, ' +
        '   actual_answer, ' +
        '   requires_actual_answer_yn, ' +
        '   shared_map_yn, ' +
        '   before_image_link, ' +
        '   passage_header, ' +
        '   display_passage_yn, ' +
        '   other_passage, ' +
        '   question_narration \n' +
        'from iquiz.IQV_STUDENT_QUIZ_QUESTIONS \n' +
        'where sqh_id = :sqh_id',
        {
            sqh_id: sqheaders.id
        },

        function (err, results) {
            if (err) throw err;
            sqheaders.questions = [];
            results.rows.forEach(function (row) {
                var qlist = {};
                qlist.id = row[0];
                qlist.question_number = row[1];
                qlist.questionTypeId = row[2];
                qlist.image = row[3];
                qlist.answer_narration = row[4];
                qlist.answer_image_link = row[5];
                qlist.passage = row[6];
                qlist.actual_answer = row[7];
                qlist.requires_actual_answer_yn = row[8];
                qlist.shared_map_yn = row[9];
                qlist.before_image_link = row[10];
                qlist.passage_header = row[11];
                qlist.display_passage_yn = row[12];
                qlist.other_passage = row[13];
                qlist.name = row[14];
                sqheaders.questions.push(qlist);
            });
            async.eachSeries(
                sqheaders.questions,
                function (qlist, cb) {
                    connection.execute(
                        ' select answer_id, \n' +
                        '  answer_narration, ' +
                        '  isAnswer, ' +
                        '  question_sys_id\n' +
                        ' from iquiz.iq_student_quiz_answers \n' +
                        ' where sqq_id = :sqq_id',
                        {
                            sqq_id: qlist.id
                        },
                        function (err, results) {
                            if (err) {
                                cb(err);
                                return;
                            }
                            qlist.options = [];
                            results.rows.forEach(function (row) {
                                var qa = {};
                                qa.id = row[0];
                                qa.name = row[1];
                                qa.isAnswer = row[2];
                                qa.questionId = row[3];
                                qlist.options.push(qa);
                            });
                            cb();
                        }
                    );
                },
                function (err) {
                    if (err) throw err;
                    //callback(null, JSON.stringify(department));
                    res.send(JSON.stringify(sqheaders));
                    connection.release(function (err) {
                        if (err) {
                            console.error(err);
                        }
                    });
                }
            );

            //res.send(JSON.stringify(sqheaders));

        }   ///function (err,results) 

    );
}